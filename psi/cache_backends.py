"""Encryption backends for the PSI secret cache.

Each backend wraps a raw bytes payload in a keyed envelope. Two backends are
supported today:

- ``TpmBackend``: AES-256-GCM with a key unsealed by ``systemd-creds`` from the
  host TPM2 and delivered via ``$CREDENTIALS_DIRECTORY/psi-cache-key``. The key
  is read once at service startup and held in memory for the lifetime of the
  process.
- ``HsmBackend``: hybrid RSA-OAEP-SHA256 + AES-256-GCM using a Nitrokey HSM.
  Reuses ``psi.providers.nitrokeyhsm.crypto`` for the envelope format. The HSM
  is only required at startup (for decrypt); writes use the cached public key
  and are software-only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from psi.errors import ConfigError, ProviderError

if TYPE_CHECKING:
    from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig

TPM_BACKEND_TAG = 0x01
HSM_BACKEND_TAG = 0x02

_TPM_NONCE_SIZE = 12
_TPM_KEY_SIZE = 32
_CREDENTIAL_NAME = "psi-cache-key"


class CacheBackend(Protocol):
    """Symmetric encrypt/decrypt interface for the cache envelope payload."""

    tag: int

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and return the backend payload bytes."""

    def decrypt(self, payload: bytes) -> bytes:
        """Decrypt ``payload`` (produced by :meth:`encrypt`) and return plaintext."""

    def close(self) -> None:
        """Release any held resources (HSM sessions, key material)."""


class TpmBackend:
    """AES-256-GCM backend whose key is unsealed from the host TPM2.

    The raw 32-byte key must be present at ``$CREDENTIALS_DIRECTORY/psi-cache-key``
    when :meth:`open` is called. On Fedora CoreOS this is wired up via
    ``LoadCredentialEncrypted=psi-cache-key:/etc/psi/cache.key`` on the
    ``psi-secrets.service`` unit.
    """

    tag = TPM_BACKEND_TAG

    def __init__(self, key: bytes | None = None) -> None:
        """Construct a TPM backend.

        Args:
            key: Optional raw 32-byte AES key. Only used during provisioning
                (``psi cache init --backend tpm``) where the key is held in
                memory before being sealed. At runtime, leave this None and
                call :meth:`open` to read the key from ``$CREDENTIALS_DIRECTORY``.
        """
        if key is not None and len(key) != _TPM_KEY_SIZE:
            msg = f"TPM key must be {_TPM_KEY_SIZE} bytes, got {len(key)}"
            raise ConfigError(msg)
        self._key: bytes | None = key

    def open(self) -> None:
        """Read the AES key from ``$CREDENTIALS_DIRECTORY``.

        Does nothing if a key was already supplied to :meth:`__init__`.

        Raises:
            ConfigError: If the credential is unavailable or the wrong size.
        """
        if self._key is not None:
            return
        creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if not creds_dir:
            msg = (
                "TPM cache backend requires $CREDENTIALS_DIRECTORY. "
                "Add 'LoadCredentialEncrypted=psi-cache-key:/etc/psi/cache.key' "
                "to the psi serve unit, or run 'psi cache init --backend tpm'."
            )
            raise ConfigError(msg)

        key_path = Path(creds_dir) / _CREDENTIAL_NAME
        if not key_path.exists():
            msg = (
                f"TPM cache key not found at {key_path}. "
                "Run 'psi cache init --backend tpm' to provision it."
            )
            raise ConfigError(msg)

        data = key_path.read_bytes()
        if len(data) != _TPM_KEY_SIZE:
            msg = (
                f"TPM cache key has wrong size: expected {_TPM_KEY_SIZE} bytes, "
                f"got {len(data)}. Re-run 'psi cache init --backend tpm'."
            )
            raise ConfigError(msg)

        self._key = data

    def close(self) -> None:
        """Best-effort scrub of the AES key from memory."""
        if self._key is not None:
            self._key = None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return ``nonce || AES-256-GCM(plaintext)``."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if self._key is None:
            msg = "TpmBackend.encrypt called before open()"
            raise ProviderError(msg, provider_name="cache")

        nonce = os.urandom(_TPM_NONCE_SIZE)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, payload: bytes) -> bytes:
        """Decrypt a ``nonce || ciphertext+tag`` payload."""
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if self._key is None:
            msg = "TpmBackend.decrypt called before open()"
            raise ProviderError(msg, provider_name="cache")
        if len(payload) < _TPM_NONCE_SIZE + 16:
            msg = "TPM cache payload truncated"
            raise ProviderError(msg, provider_name="cache")

        nonce = payload[:_TPM_NONCE_SIZE]
        ciphertext = payload[_TPM_NONCE_SIZE:]
        aesgcm = AESGCM(self._key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            msg = "TPM cache decrypt failed: ciphertext tampered or wrong key"
            raise ProviderError(msg, provider_name="cache") from e


class HsmBackend:
    """Hybrid RSA-OAEP + AES-256-GCM backend using a Nitrokey HSM.

    Reuses the envelope format from :mod:`psi.providers.nitrokeyhsm.crypto`.
    The HSM RSA private key is only used at :meth:`open` time to unwrap any
    existing cache (and thereafter for reads). Writes are software-only once
    the public key has been cached.
    """

    tag = HSM_BACKEND_TAG

    def __init__(self, config: NitrokeyHSMConfig) -> None:
        self._config = config
        self._session: object | None = None
        self._public_key_der: bytes | None = None

    def open(self) -> None:
        """Open a PKCS#11 session and cache the HSM public key."""
        from psi.providers.nitrokeyhsm.pin import resolve_pin
        from psi.providers.nitrokeyhsm.pkcs11 import PKCS11Session

        pin = resolve_pin(self._config)
        session = PKCS11Session(self._config)
        session.open(pin)
        try:
            self._public_key_der = session.get_public_key_der()
        except Exception:
            session.close()
            raise
        self._session = session

    def close(self) -> None:
        """Close the PKCS#11 session and drop cached key material."""
        if self._session is not None:
            # Duck-typed so tests can substitute a fake session.
            close = getattr(self._session, "close", None)
            if callable(close):
                close()
            self._session = None
        self._public_key_der = None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Produce a hybrid envelope using the cached HSM public key."""
        from psi.providers.nitrokeyhsm.crypto import encrypt as hybrid_encrypt

        if self._public_key_der is None:
            msg = "HsmBackend.encrypt called before open()"
            raise ProviderError(msg, provider_name="cache")
        return hybrid_encrypt(plaintext, self._public_key_der)

    def decrypt(self, payload: bytes) -> bytes:
        """Decrypt a hybrid envelope via the HSM's RSA private key."""
        from psi.providers.nitrokeyhsm.crypto import decrypt as hybrid_decrypt

        if self._session is None:
            msg = "HsmBackend.decrypt called before open()"
            raise ProviderError(msg, provider_name="cache")
        try:
            return hybrid_decrypt(payload, self._session)  # ty: ignore[invalid-argument-type]
        except ProviderError:
            raise
        except Exception as e:
            msg = f"HSM cache decrypt failed: {e}"
            raise ProviderError(msg, provider_name="cache") from e


def make_backend(name: str, settings: object) -> CacheBackend:
    """Construct a backend by name, reading provider config from ``settings``.

    Args:
        name: Backend identifier (``"tpm"`` or ``"hsm"``).
        settings: ``PsiSettings`` instance; only ``providers`` is read.

    Raises:
        ConfigError: If the backend name is unknown or required config is missing.
    """
    if name == "tpm":
        return TpmBackend()
    if name == "hsm":
        from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig

        providers = getattr(settings, "providers", {}) or {}
        raw = providers.get("nitrokeyhsm")
        if not raw:
            msg = (
                "HSM cache backend selected but providers.nitrokeyhsm is not configured. "
                "Add a nitrokeyhsm provider block or choose a different backend."
            )
            raise ConfigError(msg)
        return HsmBackend(NitrokeyHSMConfig.model_validate(raw))
    msg = f"Unknown cache backend: {name!r}. Valid: 'tpm', 'hsm'."
    raise ConfigError(msg)
