"""Hybrid encryption: AES-256-GCM data encryption + RSA-OAEP key wrapping.

Envelope format:
    key_len (2 bytes, big-endian) ||
    encrypted_aes_key (key_len bytes) ||
    nonce (12 bytes) ||
    ciphertext+tag (remaining bytes, last 16 bytes are GCM tag)

Encryption (software-only, uses public key):
    1. Generate random 32-byte AES key
    2. Generate random 12-byte nonce
    3. AES-256-GCM encrypt plaintext → ciphertext + 16-byte tag
    4. RSA-OAEP-SHA256 encrypt AES key with public key
    5. Pack envelope

Decryption (requires HSM for step 2):
    1. Unpack envelope
    2. HSM decrypts AES key via PKCS#11 RSA-OAEP
    3. AES-256-GCM decrypts ciphertext
"""

from __future__ import annotations

import os
import struct
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_der_public_key

if TYPE_CHECKING:
    from psi.providers.nitrohsm.pkcs11 import PKCS11Session

_AES_KEY_SIZE = 32
_NONCE_SIZE = 12
_KEY_LEN_HEADER = 2


def encrypt(plaintext: bytes, public_key_der: bytes) -> bytes:
    """Encrypt plaintext using hybrid RSA-OAEP + AES-256-GCM.

    Args:
        plaintext: Data to encrypt (any length).
        public_key_der: RSA public key in DER format.

    Returns:
        Encrypted envelope bytes.
    """
    public_key = load_der_public_key(public_key_der)

    aes_key = os.urandom(_AES_KEY_SIZE)
    nonce = os.urandom(_NONCE_SIZE)

    aesgcm = AESGCM(aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None,
        ),
    )

    key_len = struct.pack(">H", len(encrypted_aes_key))
    return key_len + encrypted_aes_key + nonce + ciphertext_and_tag


def decrypt(envelope: bytes, session: PKCS11Session) -> bytes:
    """Decrypt an envelope using the HSM for RSA-OAEP key unwrap.

    Args:
        envelope: Encrypted envelope from encrypt().
        session: Open PKCS#11 session with logged-in HSM.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If the envelope is malformed.
    """
    if len(envelope) < _KEY_LEN_HEADER:
        msg = "Envelope too short"
        raise ValueError(msg)

    key_len = struct.unpack(">H", envelope[:_KEY_LEN_HEADER])[0]
    offset = _KEY_LEN_HEADER

    if len(envelope) < offset + key_len + _NONCE_SIZE:
        msg = "Envelope truncated"
        raise ValueError(msg)

    encrypted_aes_key = envelope[offset : offset + key_len]
    offset += key_len

    nonce = envelope[offset : offset + _NONCE_SIZE]
    offset += _NONCE_SIZE

    ciphertext_and_tag = envelope[offset:]

    aes_key = session.decrypt_rsa_oaep(encrypted_aes_key)

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
