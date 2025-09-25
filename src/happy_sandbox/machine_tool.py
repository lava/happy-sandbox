"""Machine management tool - Fetch, decrypt, and delete machine data from happy-server.

Usage:
    machine-tool list [--machine-id=<id>] [--credentials-dir=<dir>] [--raw] [--json] [--verbose]
    machine-tool delete <machine-id> [--credentials-dir=<dir>] [--confirm]
    machine-tool -h | --help
    machine-tool --version

Commands:
    list                              List machines (default command for backward compatibility)
    delete                            Delete a specific machine

Options:
    -h --help                         Show this screen.
    --version                         Show version.
    --machine-id=<id>                 Specific machine ID to fetch (default: fetch all)
    --credentials-dir=<dir>           Credentials directory [default: ~/.happy/daemon]
    --raw                             Show raw encrypted data without decryption
    --json                            Output as JSON format
    --verbose                         Show full machine details (default: only ID and status)
    --confirm                         Skip confirmation prompt for delete

Examples:
    machine-tool list                                   # List all machines (ID and status only)
    machine-tool list --verbose                        # List all machines with full details
    machine-tool list --machine-id=abc123              # Get specific machine info
    machine-tool list --raw                            # Show raw encrypted data
    machine-tool list --json                           # Output in JSON format
    machine-tool delete abc123                         # Delete machine (with confirmation)
    machine-tool delete abc123 --confirm               # Delete machine without confirmation
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import httpx
from docopt import docopt  # type: ignore

from happy_sandbox.credentials import (
    load_credentials,
    get_encryption_key,
    get_encryption_variant,
    CredentialsType,
    get_default_credentials_dir,
)
from happy_sandbox.encryption import decrypt, decode_base64


def format_machine_info(
    machine: Dict[str, Any],
    credentials: Optional[CredentialsType] = None,
    show_raw: bool = False,
) -> Dict[str, Any]:
    """Format machine info for display."""
    formatted = {
        "id": machine["id"],
        "active": machine["active"],
        "activeAt": machine["activeAt"],
        "createdAt": machine["createdAt"],
        "updatedAt": machine["updatedAt"],
        "metadataVersion": machine["metadataVersion"],
        "daemonStateVersion": machine["daemonStateVersion"],
    }

    if show_raw or not credentials:
        # Show raw encrypted data
        formatted["metadataRaw"] = machine["metadata"]
        formatted["daemonStateRaw"] = machine.get("daemonState")
        formatted["dataEncryptionKeyRaw"] = machine.get("dataEncryptionKey")
    else:
        # Decrypt and show readable data
        try:
            encryption_key = get_encryption_key(credentials)
            encryption_variant = get_encryption_variant(credentials)

            # Decrypt metadata
            if machine["metadata"]:
                metadata_bytes = decode_base64(machine["metadata"])
                decrypted_metadata = decrypt(
                    encryption_key, encryption_variant, metadata_bytes
                )
                formatted["metadata"] = decrypted_metadata
            else:
                formatted["metadata"] = None

            # Decrypt daemon state
            if machine.get("daemonState"):
                daemon_state_bytes = decode_base64(machine["daemonState"])
                decrypted_daemon_state = decrypt(
                    encryption_key, encryption_variant, daemon_state_bytes
                )
                formatted["daemonState"] = decrypted_daemon_state
            else:
                formatted["daemonState"] = None

            # Show data encryption key if present
            if machine.get("dataEncryptionKey"):
                formatted["dataEncryptionKey"] = machine["dataEncryptionKey"]
            else:
                formatted["dataEncryptionKey"] = None

        except Exception as e:
            formatted["decryptionError"] = str(e)
            formatted["metadataRaw"] = machine["metadata"]
            formatted["daemonStateRaw"] = machine.get("daemonState")

    return formatted


async def fetch_machines(
    server_url: str, token: str, machine_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetch machine data from the API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient() as client:
        if machine_id:
            # Fetch specific machine
            response = await client.get(
                f"{server_url}/v1/machines/{machine_id}", headers=headers
            )
            response.raise_for_status()
            data = response.json()
            return [data["machine"]]
        else:
            # Fetch all machines
            response = await client.get(f"{server_url}/v1/machines", headers=headers)
            response.raise_for_status()
            return response.json()


async def delete_machine(server_url: str, token: str, machine_id: str) -> bool:
    """Delete a machine via the API."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient() as client:
        response = await client.delete(
            f"{server_url}/v1/machines/{machine_id}", headers=headers
        )
        response.raise_for_status()
        return True


def print_simple_machine(machine_info: Dict[str, Any]) -> None:
    """Print machine info in simple format (ID and status only)."""
    status = "Active" if machine_info["active"] else "Inactive"
    print(f"{machine_info['id']}\t{status}")


def print_formatted_machine(
    machine_info: Dict[str, Any], as_json: bool = False, verbose: bool = True
) -> None:
    """Print machine info in a readable format."""
    if as_json:
        print(json.dumps(machine_info, indent=2))
        return

    if not verbose:
        print_simple_machine(machine_info)
        return

    print(f"Machine ID: {machine_info['id']}")
    print(f"Status: {'Active' if machine_info['active'] else 'Inactive'}")
    print(f"Active At: {machine_info['activeAt']}")
    print(f"Created At: {machine_info['createdAt']}")
    print(f"Updated At: {machine_info['updatedAt']}")
    print(f"Metadata Version: {machine_info['metadataVersion']}")
    print(f"Daemon State Version: {machine_info['daemonStateVersion']}")

    if "metadata" in machine_info:
        print(f"Metadata (decrypted): {json.dumps(machine_info['metadata'], indent=2)}")
    elif "metadataRaw" in machine_info:
        print(f"Metadata (encrypted): {machine_info['metadataRaw']}")

    if "daemonState" in machine_info:
        if machine_info["daemonState"]:
            print(
                f"Daemon State (decrypted): {json.dumps(machine_info['daemonState'], indent=2)}"
            )
        else:
            print("Daemon State: None")
    elif "daemonStateRaw" in machine_info:
        if machine_info["daemonStateRaw"]:
            print(f"Daemon State (encrypted): {machine_info['daemonStateRaw']}")
        else:
            print("Daemon State: None")

    if machine_info.get("dataEncryptionKey"):
        print(f"Data Encryption Key: {machine_info['dataEncryptionKey']}")

    if "decryptionError" in machine_info:
        print(f"⚠️  Decryption Error: {machine_info['decryptionError']}")


async def handle_list_command(
    args: Dict[str, Any], credentials: CredentialsType
) -> int:
    """Handle the list command."""
    # Fetch machine data
    try:
        machines = await fetch_machines(
            credentials.server_url, credentials.token, args["--machine-id"]
        )
    except httpx.HTTPError as e:
        print(f"❌ Failed to fetch machines: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    if not machines:
        print("No machines found.")
        return 0

    # Format and display results
    show_raw = args["--raw"]
    as_json = args["--json"]
    verbose = args["--verbose"]

    if as_json and len(machines) > 1:
        # Output all machines as JSON array
        formatted_machines = [
            format_machine_info(machine, credentials, show_raw) for machine in machines
        ]
        print(json.dumps(formatted_machines, indent=2))
    else:
        # Add header for simple output
        if not verbose and not as_json and len(machines) > 1:
            print("ID\tStatus")
            print("-" * 30)

        # Display each machine
        for i, machine in enumerate(machines):
            if verbose and i > 0:
                print("\n" + "=" * 50 + "\n")

            formatted = format_machine_info(machine, credentials, show_raw)
            print_formatted_machine(formatted, as_json, verbose)

    return 0


async def handle_delete_command(
    args: Dict[str, Any], credentials: CredentialsType
) -> int:
    """Handle the delete command."""
    machine_id = args["<machine-id>"]

    if not args["--confirm"]:
        # Ask for confirmation
        response = input(
            f"Are you sure you want to delete machine {machine_id}? (y/N): "
        )
        if response.lower() not in ["y", "yes"]:
            print("Delete cancelled.")
            return 0

    try:
        await delete_machine(credentials.server_url, credentials.token, machine_id)
        print(f"✅ Successfully deleted machine {machine_id}")
        return 0
    except httpx.HTTPError as e:
        print(f"❌ Failed to delete machine: {e}", file=sys.stderr)
        if hasattr(e, "response") and e.response.status_code == 404:
            print(f"Machine {machine_id} not found", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


async def main() -> int:
    """Main entry point."""
    args = docopt(__doc__, version="machine-tool 0.2.0")

    # Load credentials
    credentials_dir = args["--credentials-dir"] or get_default_credentials_dir()
    credentials = load_credentials(credentials_dir)

    if not credentials:
        print(f"❌ No credentials found in {credentials_dir}", file=sys.stderr)
        print(
            "Please run authentication first with happy-daemon connect", file=sys.stderr
        )
        return 1

    # Determine command (backward compatibility: default to list if no command specified)
    if args["list"] or (not args["delete"]):
        return await handle_list_command(args, credentials)
    elif args["delete"]:
        return await handle_delete_command(args, credentials)
    else:
        print("❌ Unknown command", file=sys.stderr)
        return 1


def sync_main() -> int:
    """Synchronous wrapper for async main."""
    import asyncio

    return asyncio.run(main())


if __name__ == "__main__":
    raise SystemExit(sync_main())
