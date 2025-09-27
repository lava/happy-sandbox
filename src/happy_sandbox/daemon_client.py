"""Daemon client implementation for connecting to Happy server."""

import asyncio
import base64
import json
import os
import pty
import signal
import platform
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Optional, Dict, Any, Callable

import socketio
from pydantic import BaseModel, Field

from happy_sandbox.credentials import (
    CredentialsType,
    DataKeyCredentials,
    encrypt_machine_data_key_for_frontend,
)
from happy_sandbox.encryption import encrypt, decrypt
from happy_sandbox.session_supervisor import SessionSupervisor


def _get_project_version() -> str:
    """Get version from pyproject.toml."""
    try:
        project_root = Path(__file__).parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        return data["project"]["version"]
    except Exception:
        return "0.1.0"  # Fallback version


def _get_project_root() -> str:
    """Get the project root directory (equivalent to CLI's projectPath)."""
    return str(Path(__file__).parent.parent.parent)


class MachineMetadata(BaseModel):
    """Static machine information."""

    host: str = Field(default_factory=socket.gethostname)
    platform: str = Field(default_factory=platform.system)
    happyCliVersion: str = Field(default_factory=_get_project_version)
    homeDir: str = Field(default_factory=lambda: str(Path.home()))
    happyHomeDir: str = Field(default_factory=lambda: str(Path.home() / ".happy"))
    happyLibDir: str = Field(default_factory=_get_project_root)


class DaemonState(BaseModel):
    """Dynamic daemon state."""

    status: str = "running"
    pid: Optional[int] = Field(default_factory=os.getpid)
    started_at: Optional[int] = None


class SpawnSessionOptions(BaseModel):
    """Options for spawning a Happy session."""

    directory: str
    session_id: Optional[str] = None
    machine_id: str
    approved_new_directory_creation: bool = True
    token: Optional[str] = None
    agent: str = "claude"


class SpawnSessionResult(BaseModel):
    """Result of spawning a Happy session."""

    type: str  # 'success', 'error', 'requestToApproveDirectoryCreation'
    sessionId: Optional[str] = None
    errorMessage: Optional[str] = None
    directory: Optional[str] = None
    message: Optional[str] = None


class TrackedSession(BaseModel):
    """Information about a tracked session."""

    started_by: str
    pid: int
    happy_session_id: Optional[str] = None
    happy_session_metadata: Optional[Dict[str, Any]] = None
    directory_created: bool = False
    message: Optional[str] = None
    credentials_file: Optional[str] = None  # Path to temporary credentials file


class HappyDaemon:
    """Happy daemon that connects to the server as a machine."""

    def __init__(
        self,
        server_url: str,
        machine_id: str,
        encryption_key: bytes,
        token: Optional[str] = None,
        encryption_variant: str = "legacy",
        credentials: Optional[CredentialsType] = None,
    ):
        self.server_url = server_url
        self.machine_id = machine_id
        self.encryption_key = encryption_key
        self.encryption_variant = encryption_variant
        self.credentials = credentials
        self.token = token
        self.sio = socketio.AsyncClient()
        self.shutdown_requested = False

        # Setup metadata and initial state
        self.metadata = MachineMetadata()
        self.daemon_state = DaemonState(started_at=self._current_time_ms())

        # Session tracking
        self.tracked_sessions: Dict[int, TrackedSession] = {}
        self.session_awaiters: Dict[int, Callable[[TrackedSession], None]] = {}

        # Session supervisor for forwarding messages
        self.session_supervisor: Optional[SessionSupervisor] = None

        # Setup socket event handlers
        self._setup_socket_handlers()

    def _current_time_ms(self) -> int:
        """Get current time in milliseconds."""
        import time

        return int(time.time() * 1000)


    def _setup_socket_handlers(self) -> None:
        """Setup socket.io event handlers."""

        @self.sio.event
        async def connect():
            print(f"Connected to Happy server at {self.server_url}")
            await self._register_machine()

        @self.sio.event
        async def disconnect():
            print("Disconnected from Happy server")

        @self.sio.event
        async def connect_error(data):
            print(f"Connection error: {data}")

        @self.sio.on('rpc-request')
        async def rpc_request(data: Dict[str, Any]):
            """Handle RPC requests from the server."""
            print("received rpc request")
            method = data.get("method", "")
            params_encrypted = data.get("params", "")

            try:
                # Decrypt the params
                params = self._decrypt_params(params_encrypted)
                if params is None:
                    print(f"Failed to decrypt params for method: {method}")
                    return self._encrypt_response(
                        {"error": "Failed to decrypt request parameters"}
                    )

                print(f"Received RPC request: {method}")

                if method.endswith("spawn-happy-session"):
                    response = await self._handle_spawn_session(params)
                elif method.endswith("stop-session"):
                    response = await self._handle_stop_session(params)
                elif method.endswith("stop-daemon"):
                    response = await self._handle_stop_daemon(params)
                else:
                    response = self._encrypt_response(
                        {"error": f"Unknown method: {method}"}
                    )

                return response
            except Exception as e:
                return self._encrypt_response({"error": str(e)})

        @self.sio.event
        async def update(data: Dict[str, Any]):
            """Handle update events from server."""
            print(f"Received update event: {data.get('body', {}).get('t', 'unknown')}")

        @self.sio.on("rpc-registered")
        async def rpc_registered(data: Dict[str, Any]):
            """Handle update events from server."""
            print(f"rpc registered")


    def _decrypt_params(self, params_encrypted: str) -> Optional[Dict[str, Any]]:
        """Decrypt request parameters."""
        try:
            if not params_encrypted:
                return {}

            # Decode base64 to bytes
            encrypted_data = base64.b64decode(params_encrypted)

            # Decrypt using the appropriate method
            decrypted = decrypt(
                self.encryption_key, self.encryption_variant, encrypted_data
            )
            return decrypted
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def _encrypt_response(self, data: Dict[str, Any]) -> str:
        """Encrypt response data."""
        try:
            # Encrypt the data
            encrypted_data = encrypt(self.encryption_key, self.encryption_variant, data)

            # Encode as base64 for transmission
            return base64.b64encode(encrypted_data).decode("ascii")
        except Exception as e:
            print(f"Encryption error: {e}")
            # Fallback to plain JSON if encryption fails
            return json.dumps({"error": "Encryption failed"})

    async def _update_daemon_state(self) -> None:
        """Update daemon state on the server via socket message."""
        # Track daemon state version (will be updated from server responses)
        if not hasattr(self, "_daemon_state_version"):
            self._daemon_state_version = 0

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Update local daemon state with current info
                self.daemon_state.status = "running"
                self.daemon_state.pid = os.getpid()
                self.daemon_state.started_at = self._current_time_ms()

                # Encrypt the daemon state
                daemon_state_encrypted = base64.b64encode(
                    encrypt(
                        self.encryption_key,
                        self.encryption_variant,
                        self.daemon_state.model_dump(),
                    )
                ).decode("ascii")

                # Send machine-update-state message via socket
                response = await self.sio.call(
                    "machine-update-state",
                    {
                        "machineId": self.machine_id,
                        "daemonState": daemon_state_encrypted,
                        "expectedVersion": self._daemon_state_version,
                    },
                )

                if response.get("result") == "success":
                    self._daemon_state_version = response.get("version", 0)
                    print(
                        f"✓ Daemon state updated successfully (version {self._daemon_state_version})"
                    )
                    return
                elif response.get("result") == "version-mismatch":
                    # Update our version to match server and retry
                    server_version = response.get("version", 0)
                    if server_version > self._daemon_state_version:
                        self._daemon_state_version = server_version
                        print(
                            f"⚠ Version mismatch, updating to server version {server_version} (attempt {attempt + 1}/{max_retries})"
                        )
                        continue
                else:
                    print(
                        f"⚠ Unexpected daemon state update result: {response.get('result', 'unknown')}"
                    )
                    return

            except Exception as e:
                print(
                    f"⚠ Error updating daemon state via socket (attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt == max_retries - 1:
                    return
                await asyncio.sleep(0.5)  # Brief delay before retry

    async def _register_machine(self) -> None:
        """Register this machine with the server."""
        # First register machine via REST API to create database record
        import aiohttp

        try:
            # Encrypt metadata and daemon state
            metadata_encrypted = base64.b64encode(
                encrypt(
                    self.encryption_key,
                    self.encryption_variant,
                    self.metadata.model_dump(),
                )
            ).decode("ascii")

            daemon_state_encrypted = base64.b64encode(
                encrypt(
                    self.encryption_key,
                    self.encryption_variant,
                    self.daemon_state.model_dump(),
                )
            ).decode("ascii")

            # Prepare dataEncryptionKey for dataKey variant
            data_encryption_key = None
            if isinstance(self.credentials, DataKeyCredentials):
                # Encrypt machine data key for the frontend to decrypt
                data_encryption_key = encrypt_machine_data_key_for_frontend(
                    self.credentials
                )

            payload = {
                "id": self.machine_id,
                "metadata": metadata_encrypted,
                "daemonState": daemon_state_encrypted,
                "dataEncryptionKey": data_encryption_key,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.server_url}/v1/machines",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self.token}",
                        "Content-Type": "application/json",
                    },
                ) as response:
                    if response.status == 200:
                        print(
                            f"✓ Machine {self.machine_id} registered successfully via REST API"
                        )
                    else:
                        print(
                            f"⚠ Failed to register machine via REST API: {response.status}"
                        )
                        # Continue anyway as the socket registration might still work

        except Exception as e:
            print(f"⚠ Error registering machine via REST API: {e}")
            # Continue anyway as the socket registration might still work

        # Update daemon state to running (like happy-cli does)
        await self._update_daemon_state()

        # Initialize session supervisor
        if self.session_supervisor is None:
            self.session_supervisor = SessionSupervisor(
                server_url=self.server_url,
                machine_id=self.machine_id,
                encryption_key=self.encryption_key,
                token=self.token,
                encryption_variant=self.encryption_variant,
            )
            await self.session_supervisor.start()
            print("Session supervisor started")

        # Then register RPC handlers via socket
        machine_methods = [
            f"{self.machine_id}:spawn-happy-session",
            f"{self.machine_id}:stop-session",
            f"{self.machine_id}:stop-daemon",
        ]

        for method in machine_methods:
            await self.sio.emit("rpc-register", {"method": method})
            print(f"Registered RPC method: {method}")

    async def _handle_spawn_session(self, params: Dict[str, Any]) -> str:
        """Handle spawn session RPC request."""
        print("Handling spawn session request")
        try:
            options = SpawnSessionOptions(
                directory=params.get("directory", os.getcwd()),
                session_id=params.get("sessionId"),
                machine_id=self.machine_id,
                approved_new_directory_creation=params.get(
                    "approvedNewDirectoryCreation", True
                ),
                token=params.get("token"),
                agent=params.get("agent", "claude"),
            )

            result = await self._spawn_session(options)
            return self._encrypt_response(result.model_dump())

        except Exception as e:
            return self._encrypt_response(
                {"type": "error", "errorMessage": f"Failed to spawn session: {str(e)}"}
            )

    async def _spawn_session(self, options: SpawnSessionOptions) -> SpawnSessionResult:
        """Spawn a new Happy session."""
        print(f"Spawning session in directory: {options.directory}")

        # Check if Claude credentials exist - required for Claude sessions
        if options.agent == "claude":
            claude_credentials_path = Path.home() / ".claude" / ".credentials.json"
            if not claude_credentials_path.exists():
                return SpawnSessionResult(
                    type="error",
                    errorMessage=(
                        "Claude credentials not found. Please log in to Claude manually on this server by running "
                        "'claude auth login' or ensure ~/.claude/.credentials.json exists."
                    )
                )

        # Check if directory exists, create if needed
        directory_path = Path(options.directory)
        directory_created = False

        if not directory_path.exists():
            if not options.approved_new_directory_creation:
                return SpawnSessionResult(
                    type="requestToApproveDirectoryCreation",
                    directory=options.directory,
                )

            try:
                directory_path.mkdir(parents=True, exist_ok=True)
                directory_created = True
                print(f"Created directory: {options.directory}")
            except Exception as e:
                return SpawnSessionResult(
                    type="error",
                    errorMessage=f"Failed to create directory {options.directory}: {str(e)}",
                )

        # Create temporary credentials file for the session
        creds_file_path = None
        try:
            creds_file_path = await self._create_tmp_credentials_file()
            print(f"Created temporary credentials file at: {creds_file_path}")
        except Exception as e:
            return SpawnSessionResult(
                type="error",
                errorMessage=f"Failed to create credentials file: {str(e)}",
            )

        try:
            # Build command to spawn Happy directly (like CLI reference implementation)
            # The daemon should spawn Happy sessions, not Docker containers
            cmd = ["uv", "run", "happy-sandbox"]  # Use uv to run happy-sandbox
            # cmd.extend(["--happy-starting-mode", "remote"])
            # cmd.extend(["--started-by", "daemon"])

            # Disable daemon in spawned sessions to prevent recursive daemon spawning
            cmd.extend(["--disable-daemon"])

            # Disable ~/.happy mounting when spawned from daemon - we'll provide credentials.json instead
            cmd.extend(["--disable-happy-mount"])

            if options.agent == "codex":
                # For Codex, add appropriate flags if needed
                pass
            # For Claude (default), no special flags needed

            print(f"DEBUG: Spawning command: {' '.join(cmd)}")
            print(f"DEBUG: Working directory: {options.directory}")
            print(f"DEBUG: Agent: {options.agent}")

            # Validate command exists before attempting to spawn
            try:
                # Check if uv is available
                uv_check = subprocess.run(["which", "uv"], capture_output=True, text=True)
                if uv_check.returncode != 0:
                    print(f"ERROR: 'uv' command not found in PATH")
                    return SpawnSessionResult(
                        type="error",
                        errorMessage="'uv' command not found. Please ensure uv is installed and in PATH."
                    )
                print(f"DEBUG: Found uv at: {uv_check.stdout.strip()}")

                # Check if happy-sandbox is available via uv run
                cmd_check = subprocess.run(
                    ["uv", "run", "--help"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if cmd_check.returncode != 0:
                    print(f"ERROR: 'uv run' failed with return code {cmd_check.returncode}")
                    print(f"ERROR: uv run stderr: {cmd_check.stderr}")
                    return SpawnSessionResult(
                        type="error",
                        errorMessage=f"'uv run' command failed: {cmd_check.stderr}"
                    )
                print(f"DEBUG: 'uv run' command is available")

            except subprocess.TimeoutExpired:
                print(f"ERROR: Command validation timed out")
                return SpawnSessionResult(
                    type="error",
                    errorMessage="Command validation timed out"
                )
            except Exception as e:
                print(f"ERROR: Command validation failed: {e}")
                return SpawnSessionResult(
                    type="error",
                    errorMessage=f"Command validation failed: {str(e)}"
                )

            # Set environment variables
            env = os.environ.copy()
            if options.token:
                if options.agent == "codex":
                    # For Codex, we'd need to handle auth differently
                    pass
                else:  # claude
                    env["CLAUDE_CODE_OAUTH_TOKEN"] = options.token

            # Mount credentials file as a volume (when using Docker)
            # For now, just pass the credentials file path via environment
            env["HAPPY_CLIENT_CREDENTIALS_FILE"] = creds_file_path

            print(f"DEBUG: Environment variables set:")
            print(f"DEBUG: - CLAUDE_CODE_OAUTH_TOKEN: {'SET' if env.get('CLAUDE_CODE_OAUTH_TOKEN') else 'NOT SET'}")
            print(f"DEBUG: - HAPPY_CLIENT_CREDENTIALS_FILE: {env.get('HAPPY_CLIENT_CREDENTIALS_FILE', 'NOT SET')}")

            # Spawn the process with a pseudo-TTY to avoid "input device is not a TTY" error
            print(f"DEBUG: Creating PTY for process communication")
            try:
                master_fd, slave_fd = pty.openpty()
                print(f"DEBUG: PTY created successfully - master_fd: {master_fd}, slave_fd: {slave_fd}")
            except Exception as e:
                print(f"ERROR: Failed to create PTY: {e}")
                return SpawnSessionResult(
                    type="error",
                    errorMessage=f"Failed to create PTY: {str(e)}"
                )

            print(f"DEBUG: Starting subprocess with Popen")
            try:
                process = subprocess.Popen(
                    cmd,
                    cwd=options.directory,
                    env=env,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    start_new_session=True,  # Detach from parent
                    text=True,  # Ensure text mode for easier handling
                )
                print(f"DEBUG: Subprocess started successfully")
            except Exception as e:
                print(f"ERROR: Failed to start subprocess: {e}")
                print(f"ERROR: Command was: {' '.join(cmd)}")
                print(f"ERROR: Working directory was: {options.directory}")
                # Clean up PTY resources
                try:
                    os.close(master_fd)
                    os.close(slave_fd)
                except:
                    pass
                return SpawnSessionResult(
                    type="error",
                    errorMessage=f"Failed to start subprocess: {str(e)}"
                )

            # Close slave_fd in parent process (child will use it)
            print(f"DEBUG: Closing slave_fd {slave_fd} in parent process")
            try:
                os.close(slave_fd)
                print(f"DEBUG: Successfully closed slave_fd")
            except Exception as e:
                print(f"ERROR: Failed to close slave_fd: {e}")

            # Convert master_fd to a file-like object for easier handling
            print(f"DEBUG: Converting master_fd {master_fd} to file object")
            try:
                # Use binary mode for PTY compatibility - PTY file descriptors are not seekable
                # and don't work well with text mode buffering
                master_file = os.fdopen(master_fd, 'w+b', buffering=0)  # Binary mode, no buffering
                print(f"DEBUG: Successfully created master_file object")
            except Exception as e:
                print(f"ERROR: Failed to create master_file object: {e}")
                # Clean up resources
                try:
                    os.close(master_fd)
                except:
                    pass
                return SpawnSessionResult(
                    type="error",
                    errorMessage=f"Failed to create master file object: {str(e)}"
                )

            if process.pid is None:
                print(f"ERROR: Process PID is None - process failed to start")
                try:
                    master_file.close()
                except:
                    pass
                return SpawnSessionResult(
                    type="error",
                    errorMessage="Failed to spawn process - no PID returned",
                )

            print(f"DEBUG: Spawned process with PID {process.pid}")

            # Check if process is still alive after a brief moment
            import time
            time.sleep(0.1)  # Give process a moment to potentially crash
            poll_result = process.poll()
            if poll_result is not None:
                print(f"ERROR: Process {process.pid} exited immediately with code {poll_result}")
                try:
                    master_file.close()
                except:
                    pass
                return SpawnSessionResult(
                    type="error",
                    errorMessage=f"Process exited immediately with code {poll_result}. Check if happy-sandbox is properly installed."
                )

            print(f"DEBUG: Process {process.pid} is running successfully")

            # Start async task to forward PTY output to daemon stderr for debugging
            print(f"DEBUG: Starting PTY output forwarding task for PID {process.pid}")
            asyncio.create_task(self._forward_pty_output(process.pid, master_file))

            # Track the session
            session = TrackedSession(
                started_by="daemon",
                pid=process.pid,
                directory_created=directory_created,
                credentials_file=creds_file_path,
                message=(
                    f"The path '{options.directory}' did not exist. We created a new folder and spawned a new session there."
                    if directory_created
                    else None
                ),
            )

            self.tracked_sessions[process.pid] = session

            # For now, return a simple success with fake session ID
            # In production, this would wait for the session to report back
            session_id = f"session-{process.pid}-{self._current_time_ms()}"
            session.happy_session_id = session_id

            # Start supervising the session for message forwarding
            if self.session_supervisor:
                try:
                    await self.session_supervisor.supervise_session(
                        session_id=session_id,
                        claude_session_id=options.session_id,  # May be None initially
                        directory=options.directory,
                        pid=process.pid
                    )
                    print(f"Started supervising session {session_id}")
                except Exception as e:
                    print(f"Warning: Failed to start session supervision: {e}")

            return SpawnSessionResult(
                type="success", sessionId=session_id, message=session.message
            )

        except Exception as e:
            print(f"ERROR: Unexpected exception in _spawn_session: {e}")
            import traceback
            print(f"ERROR: Full traceback:")
            traceback.print_exc()
            return SpawnSessionResult(
                type="error", errorMessage=f"Failed to spawn session: {str(e)}"
            )

    async def _handle_stop_session(self, params: Dict[str, Any]) -> str:
        """Handle stop session RPC request."""
        print("Handling stop session request")
        try:
            session_id = params.get("sessionId", "")

            success = await self._stop_session(session_id)
            return self._encrypt_response(
                {
                    "success": success,
                    "message": f"Session {session_id} {'stopped' if success else 'not found'}",
                }
            )

        except Exception as e:
            return self._encrypt_response(
                {"success": False, "message": f"Error stopping session: {str(e)}"}
            )

    async def _stop_session(self, session_id: str) -> bool:
        """Stop a session by session ID or PID."""
        print(f"Attempting to stop session {session_id}")

        # Try to find by session ID first
        for pid, session in self.tracked_sessions.items():
            if session.happy_session_id == session_id or (
                session_id.startswith("PID-")
                and pid == int(session_id.replace("PID-", ""))
            ):
                try:
                    # Stop supervising the session
                    if self.session_supervisor:
                        await self.session_supervisor.unsupervise_session(session_id)

                    # Send SIGTERM to the process
                    os.kill(pid, signal.SIGTERM)
                    print(f"Sent SIGTERM to session {session_id} (PID: {pid})")

                    # Clean up temporary credentials file
                    if session.credentials_file:
                        try:
                            os.unlink(session.credentials_file)
                            print(f"Cleaned up credentials file: {session.credentials_file}")
                        except OSError as e:
                            print(f"Failed to clean up credentials file {session.credentials_file}: {e}")

                    # Remove from tracking
                    del self.tracked_sessions[pid]
                    print(f"Removed session {session_id} from tracking")
                    return True

                except ProcessLookupError:
                    # Process already dead
                    print(f"Process {pid} already dead, removing from tracking")
                    # Still need to stop supervision
                    if self.session_supervisor:
                        await self.session_supervisor.unsupervise_session(session_id)

                    # Clean up temporary credentials file
                    if session.credentials_file:
                        try:
                            os.unlink(session.credentials_file)
                            print(f"Cleaned up credentials file: {session.credentials_file}")
                        except OSError as e:
                            print(f"Failed to clean up credentials file {session.credentials_file}: {e}")

                    del self.tracked_sessions[pid]
                    return True
                except Exception as e:
                    print(f"Failed to kill session {session_id}: {e}")
                    return False

        print(f"Session {session_id} not found")
        return False

    async def _handle_stop_daemon(self, params: Dict[str, Any]) -> str:
        """Handle stop daemon RPC request."""
        print("Handling stop daemon request - initiating shutdown")

        # Schedule shutdown after sending response
        async def delayed_shutdown():
            await asyncio.sleep(0.1)
            self.shutdown_requested = True
            await self.shutdown()

        asyncio.create_task(delayed_shutdown())

        return self._encrypt_response({"message": "Daemon shutdown initiated"})

    async def connect(self) -> None:
        """Connect to the Happy server."""
        # Convert HTTP URL to WebSocket URL
        ws_url = self.server_url.replace("http://", "ws://").replace(
            "https://", "wss://"
        )

        try:
            await self.sio.connect(
                ws_url,
                auth={
                    "token": self.token,
                    "clientType": "machine-scoped",
                    "machineId": self.machine_id,
                },
                socketio_path="/v1/updates",
                transports=["websocket"],
            )
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            raise

    async def _cleanup_stale_sessions(self) -> None:
        """Remove stale sessions that are no longer running."""
        stale_pids = []

        for pid in self.tracked_sessions.keys():
            try:
                # Check if process is still alive (signal 0 doesn't kill, just checks)
                os.kill(pid, 0)
            except ProcessLookupError:
                # Process is dead, mark for removal
                stale_pids.append(pid)
            except Exception:
                # Other error, also mark for removal
                stale_pids.append(pid)

        for pid in stale_pids:
            print(f"Removing stale session with PID {pid}")
            session = self.tracked_sessions[pid]

            # Clean up temporary credentials file
            if session.credentials_file:
                try:
                    os.unlink(session.credentials_file)
                    print(f"Cleaned up credentials file: {session.credentials_file}")
                except OSError as e:
                    print(f"Failed to clean up credentials file {session.credentials_file}: {e}")

            del self.tracked_sessions[pid]

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat and cleanup loop."""
        while not self.shutdown_requested:
            try:
                # Clean up stale sessions
                await self._cleanup_stale_sessions()

                # Send heartbeat
                await self.sio.emit(
                    "machine-alive",
                    {
                        "machineId": self.machine_id,
                        "time": self._current_time_ms(),
                        "sessionCount": len(self.tracked_sessions),
                    },
                )

                # Wait for next heartbeat
                await asyncio.sleep(20)  # 20 second interval

            except Exception as e:
                print(f"Heartbeat error: {e}")
                await asyncio.sleep(5)

    async def run(self) -> None:
        """Run the daemon."""
        print(f"Starting Happy daemon for machine {self.machine_id}")
        print(f"Connecting to server: {self.server_url}")

        # Setup signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            print(f"Received signal {signum}, shutting down...")
            self.shutdown_requested = True
            asyncio.create_task(self.shutdown())

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            await self.connect()

            # Start heartbeat loop
            heartbeat_task = asyncio.create_task(self._heartbeat_loop())

            # Keep running until shutdown is requested
            while not self.shutdown_requested:
                await asyncio.sleep(1)

            # Cancel heartbeat when shutting down
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

        except KeyboardInterrupt:
            print("Interrupted by user")
        except Exception as e:
            print(f"Daemon error: {e}")
            raise
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Shutdown the daemon gracefully."""
        print("Shutting down daemon...")
        self.shutdown_requested = True

        # Stop all tracked sessions
        for pid, session in list(self.tracked_sessions.items()):
            try:
                print(f"Stopping session {session.happy_session_id or pid}")
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                # Already dead
                pass
            except Exception as e:
                print(f"Error stopping session {pid}: {e}")

            # Clean up temporary credentials file
            if session.credentials_file:
                try:
                    os.unlink(session.credentials_file)
                    print(f"Cleaned up credentials file: {session.credentials_file}")
                except OSError as e:
                    print(f"Failed to clean up credentials file {session.credentials_file}: {e}")

        self.tracked_sessions.clear()

        # Stop session supervisor
        if self.session_supervisor:
            await self.session_supervisor.stop()
            print("Session supervisor stopped")

        if self.sio.connected:
            await self.sio.disconnect()

        print("Daemon shutdown complete")

    async def _create_tmp_credentials_file(self) -> str:
        """Create a temporary credentials file for Happy client sessions.

        Returns the path to the temporary file that should be mounted into containers.
        The file format matches what the Happy CLI's TokenStorage expects.
        """
        try:
            # Create credentials in the format expected by Happy CLI TokenStorage
            credentials_data = {
                "token": self.token,
                "secret": base64.b64encode(self.encryption_key).decode("ascii"),
                "machine_id": self.machine_id
            }

            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                prefix="happy-credentials-",
                delete=False  # Keep file around for the session
            )

            # Write credentials to file
            json.dump(credentials_data, temp_file, indent=2)
            temp_file.close()

            # Set restrictive permissions (readable only by owner)
            os.chmod(temp_file.name, 0o600)

            return temp_file.name

        except Exception as e:
            raise Exception(f"Failed to create temporary credentials file: {e}")

    async def _forward_process_output(self, pid: int, stream, stream_name: str) -> None:
        """Forward process stdout/stderr to daemon stderr for debugging."""
        try:
            if stream is None:
                return

            # Run in thread pool to avoid blocking async loop
            loop = asyncio.get_event_loop()

            def read_stream():
                lines = []
                try:
                    for line in stream:
                        lines.append(line.rstrip())
                except Exception:
                    pass
                return lines

            # Read all output in thread pool
            lines = await loop.run_in_executor(None, read_stream)

            # Print all lines to daemon stderr
            for line in lines:
                if line:  # Skip empty lines
                    print(f"[PID {pid} {stream_name}] {line}", file=sys.stderr)

        except Exception as e:
            print(f"Error forwarding {stream_name} for PID {pid}: {e}", file=sys.stderr)
        finally:
            try:
                if stream:
                    stream.close()
            except Exception:
                pass

    async def _forward_pty_output(self, pid: int, pty_file) -> None:
        """Forward PTY output to daemon stderr for debugging."""
        print(f"DEBUG: Starting PTY output forwarding for PID {pid}")
        try:
            if pty_file is None:
                print(f"ERROR: PTY file is None for PID {pid}")
                return

            # Run in thread pool to avoid blocking async loop
            loop = asyncio.get_event_loop()

            def read_pty():
                lines = []
                buffer = b""  # Use bytes buffer since file is in binary mode
                try:
                    print(f"DEBUG: Starting PTY read loop for PID {pid}", file=sys.stderr)
                    while True:
                        try:
                            # Read from PTY in small chunks to avoid blocking
                            data = pty_file.read(1024)
                            if not data:
                                print(f"DEBUG: PTY read returned no data for PID {pid}, exiting", file=sys.stderr)
                                break

                            print(f"DEBUG: PTY read {len(data)} bytes for PID {pid}", file=sys.stderr)
                            buffer += data

                            # Process complete lines - decode bytes to string for processing
                            try:
                                text_buffer = buffer.decode('utf-8', errors='ignore')
                                while '\n' in text_buffer:
                                    line, text_buffer = text_buffer.split('\n', 1)
                                    if line.strip():  # Skip empty lines
                                        lines.append(line.rstrip())
                                        print(f"[PID {pid} PTY] {line.rstrip()}", file=sys.stderr, flush=True)

                                # Convert back to bytes for next iteration
                                buffer = text_buffer.encode('utf-8')

                            except UnicodeDecodeError:
                                # If we can't decode, just continue accumulating data
                                pass

                        except OSError as e:
                            print(f"DEBUG: PTY OSError for PID {pid}: {e}", file=sys.stderr)
                            # PTY closed or process died
                            break
                        except Exception as e:
                            print(f"DEBUG: PTY read exception for PID {pid}: {e}", file=sys.stderr)
                            break

                    # Print any remaining buffer content
                    try:
                        final_text = buffer.decode('utf-8', errors='ignore')
                        if final_text.strip():
                            lines.append(final_text.rstrip())
                            print(f"[PID {pid} PTY] {final_text.rstrip()}", file=sys.stderr, flush=True)
                    except UnicodeDecodeError:
                        pass

                except Exception as e:
                    print(f"DEBUG: PTY read outer exception for PID {pid}: {e}", file=sys.stderr)

                print(f"DEBUG: PTY read loop finished for PID {pid}, captured {len(lines)} lines", file=sys.stderr)
                return lines

            # Read PTY output in thread pool
            print(f"DEBUG: Submitting PTY read task to thread pool for PID {pid}")
            lines = await loop.run_in_executor(None, read_pty)
            print(f"DEBUG: PTY read task completed for PID {pid}, got {len(lines)} lines")

        except Exception as e:
            print(f"ERROR: Exception in PTY forwarding for PID {pid}: {e}", file=sys.stderr)
            import traceback
            print(f"ERROR: PTY forwarding traceback for PID {pid}:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        finally:
            try:
                if pty_file:
                    print(f"DEBUG: Closing PTY file for PID {pid}")
                    pty_file.close()
                    print(f"DEBUG: PTY file closed for PID {pid}")
            except Exception as e:
                print(f"ERROR: Exception closing PTY file for PID {pid}: {e}", file=sys.stderr)

    # Session supervision interface methods
    async def send_claude_session_message(
        self, session_id: str, message_data: Dict[str, Any]
    ) -> None:
        """Send a Claude session message through the supervisor."""
        if self.session_supervisor:
            await self.session_supervisor.send_claude_message(session_id, message_data)

    async def send_codex_session_message(
        self, session_id: str, message_data: Dict[str, Any]
    ) -> None:
        """Send a Codex session message through the supervisor."""
        if self.session_supervisor:
            await self.session_supervisor.send_codex_message(session_id, message_data)

    async def update_session_thinking_state(
        self, session_id: str, thinking: bool
    ) -> None:
        """Update a session's thinking state."""
        if self.session_supervisor:
            await self.session_supervisor.update_session_thinking(session_id, thinking)

    async def update_session_mode_state(self, session_id: str, mode: str) -> None:
        """Update a session's mode (local/remote)."""
        if self.session_supervisor:
            await self.session_supervisor.update_session_mode(session_id, mode)

    async def update_session_claude_id(
        self, session_id: str, claude_session_id: str
    ) -> None:
        """Update a session's Claude session ID."""
        if self.session_supervisor:
            await self.session_supervisor.update_session_claude_id(
                session_id, claude_session_id
            )

    def get_supervised_sessions(self) -> Dict[str, Any]:
        """Get information about all supervised sessions."""
        if self.session_supervisor:
            return {
                sid: session.model_dump()
                for sid, session in self.session_supervisor.get_supervised_sessions().items()
            }
        return {}
