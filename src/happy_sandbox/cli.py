"""happy-sandbox

Launch the happy sandbox container.

Usage:
    happy-sandbox [--shell] [--repo=<url>] [--append-system-prompt=<prompt>] [--mount=<mount>]... [--disable-daemon] [--disable-happy-mount] [-v | --verbose]
    happy-sandbox -h | --help
    happy-sandbox --version

Options:
    -h --help                         Show this screen.
    --version                         Show version.
    --shell                           Start an interactive bash shell inside the sandbox instead of running happy.
    --repo=<url>                      Git repository URL to clone inside the container (skips mounting local dir).
    --append-system-prompt=<prompt>   System prompt to append (forwarded to happy --append-system-prompt).
    --mount=<mount>                   Additional Docker mount options (can be specified multiple times).
                                      Format: source:destination[:options] (e.g., /host/path:/container/path:ro)
    --disable-daemon                  Disable happy daemon inside the sandbox.
    --disable-happy-mount             Don't mount ~/.happy directory; use credentials.json instead.
    -v --verbose                      Print the docker command being executed.

Environment Variables:
    HAPPY_SANDBOX_PROJECT_NAME        Override project name
    HAPPY_SANDBOX_WORKDIR             Override working directory
    HAPPY_SANDBOX_IMAGE_NAME          Docker image name (default: happy-sandbox)
    HAPPY_SANDBOX_SHELL               Start interactive shell (set to true/1)
    HAPPY_SANDBOX_APPEND_SYSTEM_PROMPT  System prompt to append
    HAPPY_SANDBOX_REPO_URL            Git repository URL to clone
    HAPPY_SANDBOX_MOUNTS              Semicolon-separated mount options
                                      (e.g., "/src1:/dst1;/src2:/dst2:ro")
    HAPPY_SANDBOX_DISABLE_DAEMON      Disable happy daemon (set to true/1)
    HAPPY_SANDBOX_DISABLE_HAPPY_MOUNT Don't mount ~/.happy directory (set to true/1)
    HAPPY_DAEMON_CREDENTIALS_FILE     Path to happy daemon credentials file to mount
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from docopt import docopt
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _print_auth_error() -> None:
    msg = (
        "Authentication required: missing ~/.claude/.credentials.json or ~/.happy/access.key.\n"
        "Please authenticate first."
    )
    print(msg, file=sys.stderr)


def _collect_claude_md_files(home: Path, cwd: Path) -> str:
    """Collect all CLAUDE.md files that should be accessible in the container."""
    combined_content = []

    # Global CLAUDE.md from ~/.claude/CLAUDE.md
    global_claude_md = home / ".claude" / "CLAUDE.md"
    if global_claude_md.exists():
        combined_content.append(
            f"# Contents of {global_claude_md} (user's private global instructions for all projects):\n"
        )
        combined_content.append(global_claude_md.read_text())
        combined_content.append("\n\n")

    # Walk up from cwd to find parent CLAUDE.md files (outside cwd)
    current = cwd.parent
    parent_claude_files = []
    while current != current.parent:  # Stop at root
        claude_md = current / "CLAUDE.md"
        if claude_md.exists():
            parent_claude_files.append(claude_md)
        current = current.parent

    # Add parent CLAUDE.md files in reverse order (root to immediate parent)
    for claude_md in reversed(parent_claude_files):
        combined_content.append(f"# Contents of {claude_md}:\n")
        combined_content.append(claude_md.read_text())
        combined_content.append("\n\n")

    # Note: Project CLAUDE.md (inside cwd) will be accessible directly via mount
    return "".join(combined_content)


class Settings(BaseSettings):
    """Configuration settings for happy-sandbox.

    All settings can be configured via environment variables with HAPPY_SANDBOX_ prefix
    or overridden via CLI arguments.
    """

    # Core settings
    project_name: str = Field(
        default_factory=lambda: Path.cwd().name,
        description="Project name, defaults to current directory name",
    )
    workdir: Optional[str] = Field(
        default=None, description="Working directory in container"
    )
    image_name: str = Field(default="happy-sandbox", description="Docker image name")

    # CLI options that can also be set via environment
    shell: bool = Field(
        default=False, description="Start interactive shell instead of happy"
    )
    repo_url: Optional[str] = Field(
        default=None, description="Git repository URL to clone"
    )
    append_system_prompt: Optional[str] = Field(
        default=None, description="System prompt to append"
    )
    mounts: List[str] = Field(
        default_factory=list, description="Additional Docker mount options"
    )
    disable_daemon: bool = Field(
        default=False, description="Disable happy daemon inside the sandbox"
    )
    disable_happy_mount: bool = Field(
        default=False, description="Don't mount ~/.happy directory; use credentials.json instead"
    )
    verbose: bool = Field(
        default=False, description="Print the docker command being executed"
    )

    # Load from environment with this prefix
    model_config = SettingsConfigDict(env_prefix="HAPPY_SANDBOX_")

    @field_validator("mounts", mode="before")
    @classmethod
    def parse_mounts(cls, v):
        """Parse mounts from string (environment) or list (CLI)."""
        if isinstance(v, str):
            # Parse semicolon-separated string from environment
            return [m.strip() for m in v.split(";") if m.strip()]
        elif v is None:
            return []
        return v

    def merge_with_cli_args(self, args: dict) -> "Settings":
        """Merge CLI arguments with settings, CLI takes precedence."""
        # Create a dict of non-None CLI values
        cli_overrides = {}

        if args.get("--shell"):
            cli_overrides["shell"] = True
        if args.get("--repo"):
            cli_overrides["repo_url"] = args["--repo"]
        if args.get("--append-system-prompt"):
            cli_overrides["append_system_prompt"] = args["--append-system-prompt"]
        if args.get("--mount"):
            cli_overrides["mounts"] = args["--mount"]
        if args.get("--disable-daemon"):
            cli_overrides["disable_daemon"] = True
        if args.get("--disable-happy-mount"):
            cli_overrides["disable_happy_mount"] = True
        if args.get("--verbose"):
            cli_overrides["verbose"] = True

        # Create new settings with CLI overrides
        return self.model_copy(update=cli_overrides)


def main() -> int:
    args = docopt(__doc__, version="happy-sandbox 0.1.0")

    home = Path.home()
    credentials = home / ".claude" / ".credentials.json"
    access_key = home / ".happy" / "access.key"

    # Check for daemon-provided credentials file
    daemon_credentials_file = os.environ.get("HAPPY_DAEMON_CREDENTIALS_FILE")

    if not (credentials.exists() or daemon_credentials_file) or not access_key.exists():
        _print_auth_error()
        return 1

    # Load configuration from environment and merge with CLI args
    settings = Settings()
    settings = settings.merge_with_cli_args(args)

    # Determine project name and workdir
    if settings.repo_url:
        # Extract project_name from repo URL
        project_name = (
            settings.repo_url.split("/")[-1].replace(".git", "").replace(".GIT", "")
        )
        workdir = settings.workdir or f"/workspace/{project_name}"
    else:
        project_name = settings.project_name
        workdir = settings.workdir or f"/workspace/{project_name}"

    image = settings.image_name

    # Collect CLAUDE.md files from outside pwd
    cwd = Path.cwd()
    combined_claude_md = _collect_claude_md_files(home, cwd)

    # Create temporary file for combined CLAUDE.md content
    # This will be automatically cleaned up when the process exits
    claude_md_file = None
    if combined_claude_md:
        claude_md_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False
        )
        claude_md_file.write(combined_claude_md)
        claude_md_file.close()

    cmd: List[str] = [
        "docker",
        "run",
        "-it",
        "-e",
        f"HAPPY_SANDBOX_PROJECT_NAME={project_name}",
    ]
    if settings.repo_url:
        cmd.extend(["-e", f"HAPPY_SANDBOX_REPO_URL={settings.repo_url}"])
    else:
        cmd.extend(
            [
                "-v",
                f"{os.getcwd()}:{workdir}",
            ]
        )
    if settings.append_system_prompt:
        cmd.extend(
            ["-e", f"HAPPY_APPEND_SYSTEM_PROMPT={settings.append_system_prompt}"]
        )
    if settings.disable_daemon:
        cmd.extend(["-e", "HAPPY_DISABLE_DAEMON=true"])
    cmd.extend(
        [
            "-v",
            f"{home}/.claude.json:/host/.claude.json:ro",
        ]
    )

    # Mount credentials files with clear naming
    if daemon_credentials_file and Path(daemon_credentials_file).exists():
        # Mount daemon-provided credentials file for Happy
        cmd.extend([
            "-v",
            f"{daemon_credentials_file}:/host/happy-credentials.json:ro",
        ])

    # Always mount Claude credentials if they exist
    if credentials.exists():
        cmd.extend([
            "-v",
            f"{credentials}:/host/claude-credentials.json:ro",
        ])

    # Only mount ~/.happy directory if not disabled
    if not settings.disable_happy_mount:
        cmd.extend([
            "-v",
            f"{home}/.happy:/home/claude/.happy",
        ])

    # Mount the combined CLAUDE.md file if we created one
    if claude_md_file:
        cmd.extend(["-v", f"{claude_md_file.name}:/host/claude-md-combined:ro"])

    # Add any additional mount options specified by the user
    for mount in settings.mounts:
        cmd.extend(["-v", mount])

    cmd.extend(
        [
            "--network=host",
            "-w",
            workdir,
            image,
        ]
    )

    clone_script = ""
    if settings.repo_url:
        clone_script = f'git clone "$HAPPY_SANDBOX_REPO_URL" {workdir}; '
    cd_script = f"cd {workdir}; "

    if settings.shell:
        # Start an interactive shell within the sandbox container
        shell_cmd = clone_script + cd_script + "bash"
        cmd += ["bash", "-c", shell_cmd]
    else:
        # Default behavior: run happy inside the container
        if settings.append_system_prompt:
            happy_cmd = (
                clone_script
                + cd_script
                + f'happy --yolo --append-system-prompt "{settings.append_system_prompt}"'
            )
        else:
            happy_cmd = clone_script + cd_script + "happy --yolo"
        cmd += ["bash", "-c", happy_cmd]

    if settings.verbose:
        print("Docker command:", " ".join(cmd), file=sys.stderr)

    try:
        result = subprocess.call(cmd)
        # Clean up temporary file
        if claude_md_file:
            os.unlink(claude_md_file.name)
        return result
    except FileNotFoundError:
        print("docker not found on PATH", file=sys.stderr)
        if claude_md_file:
            os.unlink(claude_md_file.name)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
