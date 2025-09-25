"""happy-daemon

Connect to the happy server as a daemon machine.

Usage:
    happy-daemon init --server-url=<url> --app-url=<url> [--output-dir=<dir>]
    happy-daemon reset [--server-url=<url>] [--app-url=<url>] [--output-dir=<dir>] [--credentials-dir=<dir>]
    happy-daemon run [--credentials-dir=<dir>]
    happy-daemon -h | --help
    happy-daemon --version

Commands:
    init                         Interactive login and credential setup
    reset                        Connect as a new machine to the same server/app URL
    run                          Run the daemon with existing credentials

Options:
    -h --help                    Show this screen.
    --version                    Show version.
    --server-url=<url>           Happy server URL to connect to.
    --app-url=<url>              Happy app URL for authentication.
    --output-dir=<dir>           Directory to save credentials [default: ~/.happy/daemon]
    --credentials-dir=<dir>      Directory to load credentials from [default: ~/.happy/daemon]

Environment Variables:
    HAPPY_DAEMON_SERVER_URL      Server URL (overrides credentials.json)
    HAPPY_DAEMON_APP_URL         App URL (overrides credentials.json)
    HAPPY_DAEMON_MACHINE_ID      Machine ID (overrides credentials.json)
    HAPPY_DAEMON_CREDENTIALS_DIR Credentials directory (overridden by --credentials-dir)
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any

from docopt import docopt  # type: ignore
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from happy_sandbox.auth import connect_command
from happy_sandbox.daemon_client import HappyDaemon
from happy_sandbox.credentials import (
    load_credentials,
    get_encryption_key,
    get_encryption_variant,
    get_default_credentials_dir,
)


class DaemonSettings(BaseSettings):
    """Configuration settings for happy-daemon."""

    server_url: str = Field(default="", description="Happy server URL")
    app_url: str = Field(default="", description="Happy app URL")
    machine_id: str = Field(default="", description="Machine ID for this daemon")
    credentials_dir: str = Field(
        default_factory=get_default_credentials_dir, description="Credentials directory"
    )

    model_config = SettingsConfigDict(env_prefix="HAPPY_DAEMON_")

    def merge_with_cli_args(self, args: dict) -> "DaemonSettings":
        """Merge CLI arguments with settings, CLI takes precedence."""
        cli_overrides = {}

        if args.get("--server-url"):
            cli_overrides["server_url"] = args["--server-url"]
        if args.get("--app-url"):
            cli_overrides["app_url"] = args["--app-url"]
        if args.get("--credentials-dir"):
            cli_overrides["credentials_dir"] = args["--credentials-dir"]

        return self.model_copy(update=cli_overrides)


async def main_async() -> int:
    """Async main function."""
    args = docopt(__doc__, version="happy-daemon 0.1.0")

    try:
        # Load settings from environment and merge with CLI args
        settings = DaemonSettings()
        settings = settings.merge_with_cli_args(args)

        if args["init"]:
            # Handle init command
            if not settings.server_url:
                print(
                    "Error: --server-url is required for init command", file=sys.stderr
                )
                return 1
            if not settings.app_url:
                print("Error: --app-url is required for init command", file=sys.stderr)
                return 1

            output_dir = args.get("--output-dir", get_default_credentials_dir())
            return await connect_command(
                settings.server_url, settings.app_url, output_dir
            )

        elif args["reset"]:
            # Handle reset command - connects as a new machine to same server/app URL
            # Load existing credentials to get server URL and app URL as defaults
            credentials_dir = args.get(
                "--credentials-dir", get_default_credentials_dir()
            )
            existing_credentials_file = (
                Path(credentials_dir).expanduser() / "credentials.json"
            )

            app_url_from_file = None
            if existing_credentials_file.exists():
                try:
                    with open(existing_credentials_file, "r") as f:
                        existing_data = json.load(f)
                    app_url_from_file = existing_data.get("app_url")
                except Exception:
                    pass

            existing_credentials = load_credentials(credentials_dir)

            # Use existing credentials as defaults if not provided via CLI/env
            if not settings.server_url and existing_credentials:
                settings = settings.model_copy(
                    update={"server_url": existing_credentials.server_url}
                )
            if not settings.app_url and app_url_from_file:
                settings = settings.model_copy(update={"app_url": app_url_from_file})

            # Check if we have the required URLs
            if not settings.server_url:
                print(
                    "Error: --server-url is required for reset command (no existing credentials found)",
                    file=sys.stderr,
                )
                return 1
            if not settings.app_url:
                print(
                    "Error: --app-url is required for reset command (no existing credentials found)",
                    file=sys.stderr,
                )
                return 1

            output_dir = args.get("--output-dir", get_default_credentials_dir())
            return await connect_command(
                settings.server_url, settings.app_url, output_dir
            )

        elif args["run"]:
            # Handle run command
            # Try to load credentials from file first
            credentials = load_credentials(settings.credentials_dir)

            if not credentials:
                print(
                    "Error: No valid credentials found. Run 'happy-daemon init' first.",
                    file=sys.stderr,
                )
                return 1

            # Use credentials from file as defaults, allow environment variable overrides
            if not settings.server_url:
                settings = settings.model_copy(
                    update={"server_url": credentials.server_url}
                )
            if not settings.machine_id:
                settings = settings.model_copy(
                    update={"machine_id": credentials.machine_id}
                )

            # Validate required fields
            if not settings.server_url:
                print(
                    "Error: Server URL must be in credentials.json or HAPPY_DAEMON_SERVER_URL environment variable",
                    file=sys.stderr,
                )
                return 1
            if not settings.machine_id:
                print(
                    "Error: Machine ID must be in credentials.json or HAPPY_DAEMON_MACHINE_ID environment variable",
                    file=sys.stderr,
                )
                return 1

            # Get encryption key from credentials
            encryption_key = get_encryption_key(credentials)
            encryption_variant = get_encryption_variant(credentials)

            print(f"Using {encryption_variant} encryption")

            # Create and run daemon
            daemon = HappyDaemon(
                settings.server_url,
                settings.machine_id,
                encryption_key,
                credentials.token,
                encryption_variant=encryption_variant,
                credentials=credentials,
            )
            await daemon.run()

            return 0

        else:
            print(
                "Error: Must specify either 'init', 'reset', or 'run' command",
                file=sys.stderr,
            )
            return 1

    except Exception as e:
        print(f"Failed to run command: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point."""
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
