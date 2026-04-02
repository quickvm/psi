"""Nitrokey HSM provider — encrypt/decrypt secrets via Nitrokey HSM."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig

if TYPE_CHECKING:
    from psi.settings import PsiSettings


class NitrokeyHSMProvider:
    """Secret provider that encrypts/decrypts via Nitrokey HSM.

    Store: encrypts plaintext with the HSM's public key (software-side),
           writes ciphertext blob as a JSON mapping to state_dir.
    Lookup: reads ciphertext blob, decrypts AES key via PKCS#11 on HSM,
            decrypts data with AES-GCM, returns plaintext.
    """

    name = "nitrokeyhsm"

    def __init__(self, settings: PsiSettings) -> None:
        raw = settings.providers.get("nitrokeyhsm", {})
        self.config = NitrokeyHSMConfig.model_validate(raw)
        self.state_dir = settings.state_dir
        self._session: Any = None
        self._public_key_der: bytes | None = None

    def open(self) -> None:
        """Open PKCS#11 session, log in, and cache the public key."""
        from psi.errors import ProviderError
        from psi.providers.nitrokeyhsm.pin import resolve_pin
        from psi.providers.nitrokeyhsm.pkcs11 import PKCS11Session

        try:
            pin = resolve_pin(self.config)
            self._session = PKCS11Session(self.config)
            self._session.open(pin)
            self._public_key_der = self._load_public_key()
        except ProviderError:
            raise
        except Exception as e:
            msg = f"Failed to open HSM session: {e}"
            raise ProviderError(msg, provider_name="nitrokeyhsm") from e

    def close(self) -> None:
        """Close the PKCS#11 session."""
        if self._session:
            self._session.close()
            self._session = None

    def lookup(self, mapping_data: dict) -> bytes:
        """Decrypt a secret from its stored ciphertext blob.

        Args:
            mapping_data: Dict with 'provider' and 'blob' (base64).

        Returns:
            Decrypted plaintext bytes.
        """
        from psi.errors import ProviderError
        from psi.providers.nitrokeyhsm.crypto import decrypt

        if not self._session:
            msg = "Nitrokey HSM provider is not initialized"
            raise ProviderError(msg, provider_name="nitrokeyhsm")

        blob_b64 = mapping_data.get("blob")
        if not blob_b64:
            msg = "Nitrokey HSM mapping missing 'blob' field"
            raise ProviderError(msg, provider_name="nitrokeyhsm")

        try:
            envelope = base64.b64decode(blob_b64)
            return decrypt(envelope, self._session)
        except ProviderError:
            raise
        except Exception as e:
            msg = f"HSM decryption failed: {e}"
            raise ProviderError(msg, provider_name="nitrokeyhsm") from e

    def store(self, secret_id: str, plaintext: bytes) -> None:
        """Encrypt plaintext and write as a JSON mapping to state_dir.

        Args:
            secret_id: The Podman secret ID.
            plaintext: Secret value to encrypt.
        """
        from psi.errors import ProviderError
        from psi.providers.nitrokeyhsm.crypto import encrypt

        if not self._public_key_der:
            msg = "Nitrokey HSM provider is not initialized (no public key)"
            raise ProviderError(msg, provider_name="nitrokeyhsm")

        envelope = encrypt(plaintext, self._public_key_der)
        mapping = json.dumps(
            {
                "provider": "nitrokeyhsm",
                "blob": base64.b64encode(envelope).decode(),
            }
        )

        self.state_dir.mkdir(parents=True, exist_ok=True)
        mapping_path = self.state_dir / secret_id
        mapping_path.write_text(mapping)
        mapping_path.chmod(0o600)

    def _load_public_key(self) -> bytes:
        """Load the public key from cache or extract from HSM."""
        if self.config.public_key_cache and self.config.public_key_cache.exists():
            return self.config.public_key_cache.read_bytes()

        assert self._session is not None
        der = self._session.get_public_key_der()

        if self.config.public_key_cache:
            self.config.public_key_cache.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            self.config.public_key_cache.write_bytes(der)
            self.config.public_key_cache.chmod(0o644)

        return der
