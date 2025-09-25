"""Authentication module for happy-daemon."""

import asyncio
import base64
import json
import uuid
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any

import httpx
import nacl.utils
import nacl.public
import qrcode


def encode_base64_url(data: bytes) -> str:
    """Encode bytes as base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_base64(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data)


def generate_web_auth_url(app_url: str, public_key: bytes) -> str:
    """Generate web authentication URL."""
    public_key_b64 = encode_base64_url(public_key)
    return f"{app_url}/terminal/connect#key={public_key_b64}"


def display_qr_code(data: str) -> None:
    """Display QR code in terminal."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def decrypt_with_ephemeral_key(
    encrypted_bundle: bytes, recipient_private_key: bytes
) -> Optional[bytes]:
    """Decrypt data using ephemeral key exchange."""
    try:
        # Extract components: ephemeral public key (32 bytes) + nonce (24 bytes) + encrypted data
        ephemeral_public_key = encrypted_bundle[:32]
        nonce = encrypted_bundle[32:56]
        encrypted_data = encrypted_bundle[56:]

        # Create box for decryption
        private_key = nacl.public.PrivateKey(recipient_private_key)
        public_key = nacl.public.PublicKey(ephemeral_public_key)
        box = nacl.public.Box(private_key, public_key)

        # Decrypt
        decrypted = box.decrypt(encrypted_data, nonce)
        return decrypted
    except Exception:
        return None


async def do_authentication(server_url: str, app_url: str) -> Optional[Dict[str, Any]]:
    """Perform authentication flow and return credentials."""
    print("Starting authentication process...")

    # Generate ephemeral keypair
    private_key = nacl.utils.random(32)
    keypair = nacl.public.PrivateKey(private_key)
    public_key = bytes(keypair.public_key)

    # Create authentication request
    async with httpx.AsyncClient() as client:
        try:
            print(f"Sending auth request to: {server_url}/v1/auth/request")
            response = await client.post(
                f"{server_url}/v1/auth/request",
                json={
                    "publicKey": base64.b64encode(public_key).decode("ascii"),
                    "supportsV2": True,
                },
            )
            response.raise_for_status()
            print("Auth request sent successfully")
        except Exception as e:
            print(f"Failed to send auth request: {e}")
            return None

    # Show authentication options
    print("\nChoose authentication method:")
    print("1. Web browser (recommended)")
    print("2. Mobile app (QR code)")

    while True:
        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice in ["1", "2"]:
            break
        print("Please enter 1 or 2")

    if choice == "1":
        # Web authentication
        web_url = generate_web_auth_url(app_url, public_key)
        print(f"\nOpening browser to: {web_url}")

        try:
            webbrowser.open(web_url)
            print("✓ Browser opened")
        except Exception:
            print("Could not open browser automatically")

        print("\nIf the browser did not open, please copy and paste this URL:")
        print(web_url)

    else:
        # Mobile authentication
        print("\nScan this QR code with your Happy mobile app:")
        auth_url = f"happy://terminal?{encode_base64_url(public_key)}"
        display_qr_code(auth_url)
        print(f"\nOr manually enter this URL: {auth_url}")

    # Wait for authentication
    print("\nWaiting for authentication", end="", flush=True)
    dots = 0

    async with httpx.AsyncClient() as client:
        while True:
            try:
                response = await client.post(
                    f"{server_url}/v1/auth/request",
                    json={
                        "publicKey": base64.b64encode(public_key).decode("ascii"),
                        "supportsV2": True,
                    },
                )
                response.raise_for_status()
                data = response.json()

                if data.get("state") == "authorized":
                    token = data["token"]
                    encrypted_response = decode_base64(data["response"])

                    # Decrypt the response
                    decrypted = decrypt_with_ephemeral_key(
                        encrypted_response, bytes(keypair)
                    )
                    if decrypted:
                        print("\n\n✓ Authentication successful!")

                        # Generate machine ID
                        machine_id = str(uuid.uuid4())

                        # Return credentials
                        if len(decrypted) == 32:
                            # Legacy format
                            return {
                                "token": token,
                                "secret": base64.b64encode(decrypted).decode("ascii"),
                                "machine_id": machine_id,
                                "encryption_type": "legacy",
                            }
                        elif decrypted[0] == 0:
                            # New data key format - extract frontend's public key
                            frontend_public_key = decrypted[
                                1:33
                            ]  # This is the frontend's contentKeyPair.publicKey

                            # Generate our own machine data encryption key
                            machine_data_key = nacl.utils.random(32)

                            return {
                                "token": token,
                                "machine_data_key": base64.b64encode(
                                    machine_data_key
                                ).decode("ascii"),
                                "frontend_public_key": base64.b64encode(
                                    frontend_public_key
                                ).decode("ascii"),
                                "machine_id": machine_id,
                                "encryption_type": "dataKey",
                            }

                    print("\n\nFailed to decrypt response. Please try again.")
                    return None

            except Exception as e:
                print(f"\n\nFailed to check authentication status: {e}")
                return None

            # Animate waiting dots
            print(
                f"\rWaiting for authentication{'.' * ((dots % 3) + 1)}   ",
                end="",
                flush=True,
            )
            dots += 1
            await asyncio.sleep(1)


async def connect_command(server_url: str, app_url: str, output_dir: str) -> int:
    """Handle the connect subcommand."""
    print(f"Happy Daemon - Connect to {server_url}")
    print(f"Credentials will be saved to: {output_dir}")

    # Create output directory
    output_path = Path(output_dir).expanduser()
    output_path.mkdir(parents=True, exist_ok=True)

    # Perform authentication
    credentials = await do_authentication(server_url, app_url)
    if not credentials:
        print("Authentication failed.")
        return 1

    # Save credentials
    credentials_file = output_path / "credentials.json"
    secret_key_file = output_path / "secret.key"

    with open(credentials_file, "w") as f:
        json.dump(
            {
                "token": credentials["token"],
                "machine_id": credentials["machine_id"],
                "server_url": server_url,
                "app_url": app_url,
                "encryption_type": credentials["encryption_type"],
                "machine_data_key": credentials.get("machine_data_key"),
                "frontend_public_key": credentials.get("frontend_public_key"),
            },
            f,
            indent=2,
        )

    # Save secret key
    if credentials["encryption_type"] == "legacy":
        secret_data = credentials["secret"]
    else:
        secret_data = credentials["machine_data_key"]

    with open(secret_key_file, "w") as f:
        f.write(secret_data)

    print(f"\n✓ Credentials saved to {credentials_file}")
    print(f"✓ Secret key saved to {secret_key_file}")
    print(f"\nMachine ID: {credentials['machine_id']}")
    print(f"\nTo run the daemon:")
    print(
        f"  happy-daemon run --server-url {server_url} --machine-id {credentials['machine_id']} --secret-key-file {secret_key_file}"
    )

    return 0
