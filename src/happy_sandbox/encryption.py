"""Encryption utilities matching the TypeScript implementation."""

import base64
import hashlib
import json
import os
from typing import Any, Optional, Union

import nacl.public
import nacl.secret
import nacl.utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encode_base64(buffer: bytes, variant: str = "base64") -> str:
    """Encode bytes to base64 string."""
    if variant == "base64url":
        return encode_base64_url(buffer)
    return base64.b64encode(buffer).decode("ascii")


def encode_base64_url(buffer: bytes) -> str:
    """Encode bytes to base64url string (URL-safe base64)."""
    return base64.urlsafe_b64encode(buffer).decode("ascii").rstrip("=")


def decode_base64(base64_str: str, variant: str = "base64") -> bytes:
    """Decode base64 string to bytes."""
    if variant == "base64url":
        # Convert base64url to base64
        base64_standard = base64_str.replace("-", "+").replace("_", "/")
        base64_standard += "=" * (4 - len(base64_standard) % 4) % 4
        return base64.b64decode(base64_standard)
    return base64.b64decode(base64_str)


def get_random_bytes(size: int) -> bytes:
    """Generate secure random bytes."""
    return os.urandom(size)


def libsodium_public_key_from_secret_key(seed: bytes) -> bytes:
    """Generate public key from secret key seed (matches libsodium implementation)."""
    # NOTE: This matches libsodium implementation, tweetnacl doesn't do this by default
    hashed_seed = hashlib.sha512(seed).digest()
    secret_key = hashed_seed[:32]
    keypair = nacl.public.PrivateKey(secret_key)
    return bytes(keypair.public_key)


def libsodium_encrypt_for_public_key(data: bytes, recipient_public_key: bytes) -> bytes:
    """Encrypt data for a public key using ephemeral key exchange."""
    # Generate ephemeral keypair for this encryption
    ephemeral_keypair = nacl.public.PrivateKey.generate()

    # Generate random nonce (24 bytes for box encryption)
    nonce = get_random_bytes(24)

    # Create box for encryption
    recipient_key = nacl.public.PublicKey(recipient_public_key)
    box = nacl.public.Box(ephemeral_keypair, recipient_key)

    # Encrypt the data using box (authenticated encryption)
    encrypted = box.encrypt(data, nonce).ciphertext

    # Bundle format: ephemeral public key (32 bytes) + nonce (24 bytes) + encrypted data
    result = bytes(ephemeral_keypair.public_key) + nonce + encrypted
    return result


def encrypt_legacy(data: Any, secret: bytes) -> bytes:
    """Encrypt data using legacy secretbox method."""
    nonce = get_random_bytes(24)  # nacl.secretbox nonce length
    box = nacl.secret.SecretBox(secret)
    plaintext = json.dumps(data).encode("utf-8")
    encrypted = box.encrypt(plaintext, nonce).ciphertext
    return nonce + encrypted


def decrypt_legacy(data: bytes, secret: bytes) -> Optional[Any]:
    """Decrypt data using legacy secretbox method."""
    try:
        nonce = data[:24]
        encrypted = data[24:]
        box = nacl.secret.SecretBox(secret)
        decrypted = box.decrypt(encrypted, nonce)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None


def encrypt_with_data_key(data: Any, data_key: bytes) -> bytes:
    """Encrypt data using AES-256-GCM with the data encryption key."""
    nonce = get_random_bytes(12)  # GCM uses 12-byte nonces
    aesgcm = AESGCM(data_key)

    plaintext = json.dumps(data).encode("utf-8")
    encrypted = aesgcm.encrypt(nonce, plaintext, None)

    # Extract ciphertext and auth tag (last 16 bytes)
    ciphertext = encrypted[:-16]
    auth_tag = encrypted[-16:]

    # Bundle: version(1) + nonce (12) + ciphertext + auth tag (16)
    bundle = bytes([0]) + nonce + ciphertext + auth_tag
    return bundle


def decrypt_with_data_key(bundle: bytes, data_key: bytes) -> Optional[Any]:
    """Decrypt data using AES-256-GCM with the data encryption key."""
    try:
        if len(bundle) < 1:
            return None
        if bundle[0] != 0:  # Only version 0
            return None
        if len(bundle) < 12 + 16 + 1:  # Minimum: version + nonce + auth tag
            return None

        nonce = bundle[1:13]
        auth_tag = bundle[-16:]
        ciphertext = bundle[13:-16]

        aesgcm = AESGCM(data_key)
        # Combine ciphertext and auth tag for AESGCM
        encrypted_data = ciphertext + auth_tag
        decrypted = aesgcm.decrypt(nonce, encrypted_data, None)

        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        return None


def encrypt(key: bytes, variant: str, data: Any) -> bytes:
    """Encrypt data using specified variant."""
    if variant == "legacy":
        return encrypt_legacy(data, key)
    elif variant == "dataKey":
        return encrypt_with_data_key(data, key)
    else:
        raise ValueError(f"Unknown encryption variant: {variant}")


def decrypt(key: bytes, variant: str, data: bytes) -> Optional[Any]:
    """Decrypt data using specified variant."""
    if variant == "legacy":
        return decrypt_legacy(data, key)
    elif variant == "dataKey":
        return decrypt_with_data_key(data, key)
    else:
        raise ValueError(f"Unknown encryption variant: {variant}")
