"""Credential management for happy-daemon."""

import base64
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union

from pydantic import BaseModel, Field
from happy_sandbox.encryption import (
    decode_base64,
    libsodium_encrypt_for_public_key,
    encode_base64,
)


class LegacyCredentials(BaseModel):
    """Legacy encryption credentials."""

    secret: bytes
    token: str
    machine_id: str
    server_url: str
    type: str = Field(default="legacy")


class DataKeyCredentials(BaseModel):
    """DataKey encryption credentials."""

    machine_data_key: bytes
    frontend_public_key: bytes
    token: str
    machine_id: str
    server_url: str
    type: str = Field(default="dataKey")


CredentialsType = Union[LegacyCredentials, DataKeyCredentials]


def get_default_credentials_dir() -> str:
    """Get the default credentials directory path."""
    return "~/.happy/daemon"


def load_credentials(credentials_dir: str) -> Optional[CredentialsType]:
    """Load credentials from credentials.json file."""
    credentials_path = Path(credentials_dir).expanduser() / "credentials.json"

    if not credentials_path.exists():
        return None

    try:
        with open(credentials_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    # Check encryption type
    encryption_type = data.get("encryption_type", "legacy")

    if encryption_type == "legacy":
        # Load legacy secret from secret.key file
        secret_key_file = Path(credentials_dir).expanduser() / "secret.key"
        if not secret_key_file.exists():
            return None

        try:
            secret_data = secret_key_file.read_text().strip()
            secret = base64.b64decode(secret_data)
        except Exception:
            return None

        return LegacyCredentials(
            secret=secret,
            token=data["token"],
            machine_id=data["machine_id"],
            server_url=data["server_url"],
        )

    elif encryption_type == "dataKey":
        # Load dataKey credentials
        machine_data_key_b64 = data.get("machine_data_key")
        frontend_public_key_b64 = data.get("frontend_public_key")

        if not machine_data_key_b64 or not frontend_public_key_b64:
            return None

        try:
            machine_data_key = decode_base64(machine_data_key_b64)
            frontend_public_key = decode_base64(frontend_public_key_b64)
        except Exception:
            return None

        return DataKeyCredentials(
            machine_data_key=machine_data_key,
            frontend_public_key=frontend_public_key,
            token=data["token"],
            machine_id=data["machine_id"],
            server_url=data["server_url"],
        )

    return None


def get_encryption_key(credentials: CredentialsType) -> bytes:
    """Get the encryption key for the credential type."""
    if isinstance(credentials, LegacyCredentials):
        return credentials.secret
    elif isinstance(credentials, DataKeyCredentials):
        return credentials.machine_data_key
    else:
        raise ValueError(f"Unknown credentials type: {type(credentials)}")


def get_encryption_variant(credentials: CredentialsType) -> str:
    """Get the encryption variant for the credential type."""
    if isinstance(credentials, LegacyCredentials):
        return "legacy"
    elif isinstance(credentials, DataKeyCredentials):
        return "dataKey"
    else:
        raise ValueError(f"Unknown credentials type: {type(credentials)}")


def encrypt_machine_data_key_for_frontend(credentials: DataKeyCredentials) -> str:
    """Encrypt the machine's data key for the frontend to decrypt."""
    if not isinstance(credentials, DataKeyCredentials):
        raise ValueError("This function only works with DataKey credentials")

    # Encrypt machine data key using frontend's public key
    encrypted_key = libsodium_encrypt_for_public_key(
        credentials.machine_data_key, credentials.frontend_public_key
    )

    # Add version byte (0) and encode as base64
    versioned_key = bytes([0]) + encrypted_key
    return encode_base64(versioned_key)
