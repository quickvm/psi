"""PKCS#11 session management for Nitrokey HSM via PyKCS11."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyKCS11 import (
    CKA_CLASS,
    CKA_ID,
    CKA_LABEL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_SHA256,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKU_USER,
    PyKCS11Lib,
    RSAOAEPMechanism,
)
from PyKCS11.LowLevel import CKG_MGF1_SHA256

if TYPE_CHECKING:
    from PyKCS11 import Session

    from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig


class PKCS11Session:
    """Manage a PKCS#11 session with a Nitrokey HSM."""

    def __init__(self, config: NitrokeyHSMConfig) -> None:
        self._config = config
        self._lib: PyKCS11Lib | None = None
        self._session: Session | None = None

    def open(self, pin: str) -> None:
        """Open a session and log in with the provided PIN."""
        from PyKCS11 import PyKCS11Error

        from psi.errors import ProviderError

        self._lib = PyKCS11Lib()
        self._lib.load(self._config.pkcs11_module)
        slots = self._lib.getSlotList(tokenPresent=True)
        if self._config.slot >= len(slots):
            msg = f"Slot {self._config.slot} not found. Available: {len(slots)} slots"
            raise ProviderError(msg, provider_name="nitrokeyhsm")
        self._session = self._lib.openSession(
            slots[self._config.slot],
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
        )
        try:
            self._session.login(pin, CKU_USER)
        except PyKCS11Error as e:
            if "CKR_USER_ALREADY_LOGGED_IN" in str(e):
                pass
            else:
                msg = f"HSM login failed: {e}. Check your PIN."
                raise ProviderError(msg, provider_name="nitrokeyhsm") from e

    def close(self) -> None:
        """Log out and close the session."""
        if self._session:
            import contextlib

            with contextlib.suppress(Exception):
                self._session.logout()
            with contextlib.suppress(Exception):
                self._session.closeSession()
            self._session = None
        self._lib = None

    def decrypt_rsa_oaep(self, ciphertext: bytes) -> bytes:
        """Decrypt data using the HSM's RSA private key with OAEP-SHA256."""
        from PyKCS11 import PyKCS11Error

        from psi.errors import ProviderError

        if not self._session:
            msg = "PKCS#11 session not open"
            raise ProviderError(msg, provider_name="nitrokeyhsm")

        key = self._find_private_key()
        mechanism = RSAOAEPMechanism(CKM_SHA256, CKG_MGF1_SHA256)
        try:
            result = self._session.decrypt(key, ciphertext, mechanism)
        except PyKCS11Error as e:
            msg = f"HSM decryption failed: {e}"
            raise ProviderError(msg, provider_name="nitrokeyhsm") from e
        return bytes(result)

    def get_public_key_der(self) -> bytes:
        """Extract the RSA public key in DER format from the HSM."""
        from psi.errors import ProviderError

        if not self._session:
            msg = "PKCS#11 session not open"
            raise ProviderError(msg, provider_name="nitrokeyhsm")

        key_id = bytes.fromhex(self._config.key_id)
        template = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_ID, key_id),
        ]
        objects = self._session.findObjects(template)
        if not objects:
            template = [
                (CKA_CLASS, CKO_PUBLIC_KEY),
                (CKA_LABEL, self._config.key_label),
            ]
            objects = self._session.findObjects(template)
        if not objects:
            from psi.errors import ProviderError

            msg = (
                f"Public key not found: label={self._config.key_label!r}, "
                f"id={self._config.key_id!r}"
            )
            raise ProviderError(msg, provider_name="nitrokeyhsm")

        from PyKCS11 import CKA_MODULUS, CKA_PUBLIC_EXPONENT

        attrs = self._session.getAttributeValue(
            objects[0],
            [CKA_MODULUS, CKA_PUBLIC_EXPONENT],
        )
        modulus = bytes(attrs[0])
        exponent = bytes(attrs[1])
        return _build_rsa_der_public_key(modulus, exponent)

    def _find_private_key(self) -> object:
        """Find the private key on the HSM by ID or label."""
        assert self._session is not None
        key_id = bytes.fromhex(self._config.key_id)
        template = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_ID, key_id),
        ]
        objects = self._session.findObjects(template)
        if not objects:
            template = [
                (CKA_CLASS, CKO_PRIVATE_KEY),
                (CKA_LABEL, self._config.key_label),
            ]
            objects = self._session.findObjects(template)
        if not objects:
            from psi.errors import ProviderError

            msg = (
                f"Private key not found: label={self._config.key_label!r}, "
                f"id={self._config.key_id!r}"
            )
            raise ProviderError(msg, provider_name="nitrokeyhsm")
        return objects[0]


def _build_rsa_der_public_key(modulus: bytes, exponent: bytes) -> bytes:
    """Build a DER-encoded SubjectPublicKeyInfo from raw RSA components.

    Uses the cryptography library to construct the key properly.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPublicNumbers,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    n = int.from_bytes(modulus, "big")
    e = int.from_bytes(exponent, "big")
    public_numbers = RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()
    return public_key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
