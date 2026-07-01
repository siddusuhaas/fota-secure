"""AES/RSA primitives for the packager.

See docs/FORMAT_SPEC.md for the exact algorithms/padding this must match
byte-for-byte with consumer/, and docs/THREAT_MODEL.md items 3-4 for why
keys and IVs are always freshly generated per build, never hardcoded or
reused.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_SIZE = 32  # AES-256
AES_IV_SIZE = 16  # CBC block size
AES_BLOCK_SIZE_BITS = 128


def generate_aes_key() -> bytes:
    """Fresh random AES-256 key via CSPRNG.

    A new key is generated for every build and never reused across builds
    (docs/THREAT_MODEL.md item 3) — do not cache or hardcode a return value
    from this function anywhere, including in tests.
    """
    return os.urandom(AES_KEY_SIZE)


def generate_iv() -> bytes:
    """Fresh random CBC IV via CSPRNG.

    Never zero, never reused, never derived deterministically — a
    static/zero IV leaks structural information about firmware plaintext
    across builds (docs/THREAT_MODEL.md item 4).
    """
    return os.urandom(AES_IV_SIZE)


def encrypt_payload(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encrypt with PKCS#7 padding."""
    padder = padding.PKCS7(AES_BLOCK_SIZE_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(algorithms.AES256(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_payload(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC decrypt + strip PKCS#7 padding.

    Not used in the packager's production flow (the device decrypts, see
    consumer/), but kept alongside encrypt_payload so the crypto layer can
    be round-trip tested in isolation from the rest of the pipeline.
    """
    decryptor = Cipher(algorithms.AES256(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def wrap_key(aes_key: bytes, device_public_key: rsa.RSAPublicKey) -> bytes:
    """RSA-OAEP (SHA-256) encrypt aes_key with the device's public key.

    OAEP, not PKCS#1v1.5, for this key-wrap: OAEP is the correct padding
    for RSA *encryption* (PKCS#1v1.5 encryption padding has known
    padding-oracle weaknesses). PKCS#1v1.5 is used below only for the
    *signature*, which is a different, still-current, standard use of that
    padding scheme.
    """
    return device_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key(wrapped_key: bytes, device_private_key: rsa.RSAPrivateKey) -> bytes:
    """Reverse of wrap_key.

    Production unwrap happens on-device (consumer/, in C); this exists so
    the packager's own tests can prove wrap/unwrap round-trips using real
    keygen output.
    """
    return device_private_key.decrypt(
        wrapped_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign(data: bytes, signing_private_key: rsa.RSAPrivateKey) -> bytes:
    """RSA-2048 PKCS#1v1.5 signature over SHA-256(data).

    See docs/FORMAT_SPEC.md's Signature Section: data is expected to be
    fixed_header || wrapped_key || ciphertext_payload.
    """
    return signing_private_key.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())


def verify_signature(
    data: bytes, signature: bytes, signing_public_key: rsa.RSAPublicKey
) -> bool:
    """Verify a signature produced by sign().

    Returns False on any verification failure rather than raising, so
    callers can't accidentally treat an unhandled exception as anything
    other than "not valid" (docs/THREAT_MODEL.md item 5: verify-then-decrypt
    depends on this being a clean boolean check).
    """
    try:
        signing_public_key.verify(
            signature, data, asym_padding.PKCS1v15(), hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError(f"{path} is not an RSA private key")
    return key


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError(f"{path} is not an RSA public key")
    return key
