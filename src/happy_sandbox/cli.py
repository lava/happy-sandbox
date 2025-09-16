import os
import sys
import argparse
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from pydantic import Field
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
    # Default project name: basename of current directory
    project_name: str = Field(default_factory=lambda: Path.cwd().name)
    # Workdir can be overridden via env; otherwise we derive from project_name
    workdir: str = ""
    image_name: str = "happy-sandbox"
    append_system_prompt: Optional[str] = None

    # Load from environment with this prefix
    model_config = SettingsConfigDict(env_prefix="HAPPY_SANDBOX_")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="happy-sandbox",
        description="Launch the happy sandbox container",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="Start an interactive bash shell inside the sandbox instead of running happy",
    )
    parser.add_argument(
        "--repo",
        type=str,
        help="Git repository URL to clone inside the container (skips mounting local dir)",
    )
    parser.add_argument(
        "--append-system-prompt",
        type=str,
        help="System prompt to append (forwarded to happy --append-system-prompt)",
    )
    args = parser.parse_args()

    home = Path.home()
    credentials = home / ".claude" / ".credentials.json"
    access_key = home / ".happy" / "access.key"

    if not credentials.exists() or not access_key.exists():
        _print_auth_error()
        return 1

    # Load configuration from environment via pydantic settings
    settings = Settings()
    repo_url = args.repo if hasattr(args, "repo") and args.repo else None
    append_system_prompt = (
        args.append_system_prompt
        if hasattr(args, "append_system_prompt") and args.append_system_prompt
        else settings.append_system_prompt
    )
    if repo_url:
        # Extract project_name from repo URL
        project_name = repo_url.split("/")[-1].replace(".git", "").replace(".GIT", "")
        workdir = f"/workspace/{project_name}"
    else:
        project_name = settings.project_name
        # Derive default workdir if not provided via env
        if os.environ.get("HAPPY_SANDBOX_WORKDIR"):
            workdir = settings.workdir
        else:
            workdir = f"/workspace/{project_name}"
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
    if repo_url:
        cmd.extend(["-e", f"HAPPY_SANDBOX_REPO_URL={repo_url}"])
    else:
        cmd.extend(
            [
                "-v",
                f"{os.getcwd()}:{workdir}",
            ]
        )
    if append_system_prompt:
        cmd.extend(["-e", f"HAPPY_APPEND_SYSTEM_PROMPT={append_system_prompt}"])
    cmd.extend(
        [
            "-v",
            f"{home}/.claude.json:/host/.claude.json:ro",
            "-v",
            f"{home}/.claude/.credentials.json:/host/.credentials.json:ro",
            "-v",
            f"{home}/.happy:/home/claude/.happy",
        ]
    )

    # Mount the combined CLAUDE.md file if we created one
    if claude_md_file:
        cmd.extend(["-v", f"{claude_md_file.name}:/host/claude-md-combined:ro"])

    cmd.extend(
        [
            "--network=host",
            "-w",
            workdir,
            image,
        ]
    )

    clone_script = ""
    if repo_url:
        clone_script = f'git clone "$HAPPY_SANDBOX_REPO_URL" {workdir}; '
    cd_script = f"cd {workdir}; "

    if args.shell:
        # Start an interactive shell within the sandbox container
        shell_cmd = clone_script + cd_script + "bash"
        cmd += ["bash", "-c", shell_cmd]
    else:
        # Default behavior: run happy inside the container
        if append_system_prompt:
            happy_cmd = (
                clone_script
                + cd_script
                + f'happy --yolo --append-system-prompt "{append_system_prompt}"'
            )
        else:
            happy_cmd = clone_script + cd_script + "happy --yolo"
        cmd += ["bash", "-c", happy_cmd]

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
