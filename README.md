# happy-sandbox

A small CLI that launches a Docker-based sandbox environment for Claude tooling.

## Installation

- With pipx (recommended for CLIs):

```
pipx install .
```

- With pip (editable for local development):

```
pip install -e .
```

- With uv:

```
uv pip install -e .
```

This installs `pydantic-settings` and other dependencies defined in `pyproject.toml`.

## Usage

- Ensure you are authenticated locally (credentials exist):
  - `~/.claude/.credentials.json`
  - `~/.happy/access.key`

- Optional environment variables (with defaults, prefix `HAPPY_SANDBOX_`):
  - `HAPPY_SANDBOX_PROJECT_NAME` – project name to pass through (default: basename of current directory)
  - `HAPPY_SANDBOX_WORKDIR` – container workdir (default: `/workspace/<project>`)
  - `HAPPY_SANDBOX_IMAGE_NAME` – Docker image name (default: `happy-sandbox`)

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
  -e HAPPY_SANDBOX_PROJECT_NAME=${HAPPY_SANDBOX_PROJECT_NAME:-$(basename "$(pwd)")} \
  -v "$(pwd):${HAPPY_SANDBOX_WORKDIR:-/workspace/$(basename "$(pwd)")}" \
  -v "$HOME/.claude.json:/host/.claude.json:ro" \
  -v "$HOME/.claude/.credentials.json:/host/.credentials.json:ro" \
  -v "$HOME/.happy:/home/claude/.happy" \
  --network=host \
  -w "${HAPPY_SANDBOX_WORKDIR:-/workspace/$(basename "$(pwd)")}" \
  "${HAPPY_SANDBOX_IMAGE_NAME:-happy-sandbox}" bash -c "happy"
```

If either `~/.claude/.credentials.json` or `~/.happy/access.key` is missing, the tool exits with an error asking you to authenticate first.

### Open an Interactive Shell

- To start a shell inside the sandbox container instead of running `happy`:

```
happy-sandbox --shell
```

This launches `bash` in the container with your project directory mounted and environment prepared by the entrypoint.

## Development

- Project uses `hatchling` (via `pyproject.toml`).
- Dev tools: `black`, `mypy` (see `[tool.uv]` dev-dependencies).
- MyPy is configured with the `pydantic` plugin.
