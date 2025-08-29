# happy-sandbox

A small CLI that launches a Docker-based sandbox environment for Claude tooling.

## Usage

- Ensure you are authenticated locally (credentials exist):
  - `~/.claude/.credentials.json`
  - `~/.happy/access.key`

- Set required environment variables:
  - `CLAUDE_SANDBOX_PROJECT_NAME` – project name to pass through
  - `CLAUDE_SANDBOX_WORKDIR` – container workdir to mount to (e.g. `/workspace`)
  - `IMAGE_NAME` – Docker image name to run

- Run the tool:

```
happy-sandbox
```

Or via Python module invocation:

```
python -m happy_sandbox
```

The tool executes the equivalent of:

```
docker run -it \
  -e CLAUDE_SANDBOX_PROJECT_NAME=$CLAUDE_SANDBOX_PROJECT_NAME \
  -v "$(pwd):$CLAUDE_SANDBOX_WORKDIR" \
  -v "$HOME/.claude.json:/host/.claude.json:ro" \
  -v "$HOME/.claude/.credentials.json:/host/.credentials.json:ro" \
  -v "$HOME/.happy:/home/claude/.happy" \
  --network=host \
  -w "$CLAUDE_SANDBOX_WORKDIR" \
  "$IMAGE_NAME" /bin/bash
```

If either `~/.claude/.credentials.json` or `~/.happy/access.key` is missing, the tool exits with an error asking you to authenticate first.

## Development

- Project uses `hatchling` (via `pyproject.toml`).
- Dev tools: `black`, `mypy` (see `[tool.uv]` dev-dependencies).
- MyPy is configured with the `pydantic` plugin.
