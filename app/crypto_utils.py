from __future__ import annotations

from pathlib import Path
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PathLike = Union[str, Path]


def generate_ed25519_private_key() -> Ed25519PrivateKey:
    """Create a new Ed25519 private key."""
    return Ed25519PrivateKey.generate()


def get_ed25519_public_key(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    """Derive the public key from an Ed25519 private key."""
    return private_key.public_key()


def sign_message(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a byte message with an Ed25519 private key."""
    return private_key.sign(message)


def verify_signature(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Returns True when the signature is valid and False otherwise so callers
    can handle verification failures without catching library exceptions.
    """
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def generate_fernet_key() -> bytes:
    """Generate a new Fernet symmetric key."""
    return Fernet.generate_key()


def encrypt_data(fernet_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext bytes with a Fernet key."""
    cipher = Fernet(fernet_key)
    return cipher.encrypt(plaintext)


def decrypt_data(fernet_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt Fernet ciphertext bytes with a Fernet key."""
    cipher = Fernet(fernet_key)
    return cipher.decrypt(ciphertext)


def save_private_key_to_file(
    private_key: Ed25519PrivateKey,
    file_path: PathLike,
) -> None:
    """
    Save an Ed25519 private key in PEM PKCS8 format without encryption.

    This keeps the helper simple and reusable across local edge/cloud services.
    If password-based protection is needed later, it can be added as a separate
    helper without changing the calling code.
    """
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_bytes)


def load_private_key_from_file(file_path: PathLike) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM PKCS8 file."""
    pem_bytes = Path(file_path).read_bytes()
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Loaded key is not an Ed25519 private key")
    return private_key


def save_public_key_to_file(
    public_key: Ed25519PublicKey,
    file_path: PathLike,
) -> None:
    """Save an Ed25519 public key in PEM SubjectPublicKeyInfo format."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_bytes)


def load_public_key_from_file(file_path: PathLike) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    pem_bytes = Path(file_path).read_bytes()
    public_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Loaded key is not an Ed25519 public key")
    return public_key


def save_fernet_key_to_file(fernet_key: bytes, file_path: PathLike) -> None:
    """Save a Fernet key as raw bytes."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(fernet_key)


def load_fernet_key_from_file(file_path: PathLike) -> bytes:
    """Load a Fernet key from a file."""
    return Path(file_path).read_bytes().strip()
