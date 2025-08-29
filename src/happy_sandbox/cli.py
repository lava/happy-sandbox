import os
import sys
import subprocess
from pathlib import Path


def _print_auth_error() -> None:
    msg = (
        "Authentication required: missing ~/.claude/.credentials.json or ~/.happy/access.key.\n"
        "Please authenticate first."
    )
    print(msg, file=sys.stderr)


def main() -> int:
    home = Path.home()
    credentials = home / ".claude" / ".credentials.json"
    access_key = home / ".happy" / "access.key"

    if not credentials.exists() or not access_key.exists():
        _print_auth_error()
        return 1

    env = os.environ.copy()
    project_name = env.get("CLAUDE_SANDBOX_PROJECT_NAME", "")
    workdir = env.get("CLAUDE_SANDBOX_WORKDIR")
    image = env.get("IMAGE_NAME")

    if not workdir or not image:
        print(
            "Missing required environment variables: CLAUDE_SANDBOX_WORKDIR and/or IMAGE_NAME",
            file=sys.stderr,
        )
        return 2

    cmd = [
        "docker",
        "run",
        "-it",
        "-e",
        f"CLAUDE_SANDBOX_PROJECT_NAME={project_name}",
        "-v",
        f"{os.getcwd()}:{workdir}",
        "-v",
        f"{home}/.claude.json:/host/.claude.json:ro",
        "-v",
        f"{home}/.claude/.credentials.json:/host/.credentials.json:ro",
        "-v",
        f"{home}/.happy:/home/claude/.happy",
        "--network=host",
        "-w",
        workdir,
        image,
        "/bin/bash",
    ]

    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        print("docker not found on PATH", file=sys.stderr)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())

