"""Daemon client implementation for connecting to Happy server."""

import asyncio
import base64
import json
import os
import signal
import platform
import socket
import subprocess
import sys
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
    session_id: Optional[str] = None
    error_message: Optional[str] = None
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

        @self.sio.event
        async def rpc_request(data: Dict[str, Any], callback: Callable):
            """Handle RPC requests from the server."""
            print("received rpc request")
            method = data.get("method", "")
            params_encrypted = data.get("params", "")

            try:
                # Decrypt the params
                params = self._decrypt_params(params_encrypted)
                if params is None:
                    print(f"Failed to decrypt params for method: {method}")
                    response = self._encrypt_response(
                        {"error": "Failed to decrypt request parameters"}
                    )
                    await callback(response)
                    return

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

                await callback(response)
            except Exception as e:
                error_response = self._encrypt_response({"error": str(e)})
                await callback(error_response)

        @self.sio.event
        async def update(data: Dict[str, Any]):
            """Handle update events from server."""
            print(f"Received update event: {data.get('body', {}).get('t', 'unknown')}")

        @self.sio.event
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
                    error_message=f"Failed to create directory {options.directory}: {str(e)}",
                )

        try:
            # Build command for happy-sandbox
            cmd = [sys.executable, "-m", "happy_sandbox.cli"]

            # Set environment variables
            env = os.environ.copy()
            if options.token:
                if options.agent == "codex":
                    # For Codex, we'd need to handle auth differently
                    pass
                else:  # claude
                    env["CLAUDE_CODE_OAUTH_TOKEN"] = options.token

            # Spawn the process
            process = subprocess.Popen(
                cmd,
                cwd=options.directory,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # Detach from parent
            )

            if process.pid is None:
                return SpawnSessionResult(
                    type="error",
                    error_message="Failed to spawn process - no PID returned",
                )

            print(f"Spawned process with PID {process.pid}")

            # Track the session
            session = TrackedSession(
                started_by="daemon",
                pid=process.pid,
                directory_created=directory_created,
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

            return SpawnSessionResult(
                type="success", session_id=session_id, message=session.message
            )

        except Exception as e:
            return SpawnSessionResult(
                type="error", error_message=f"Failed to spawn session: {str(e)}"
            )

    async def _handle_stop_session(self, params: Dict[str, Any]) -> str:
        """Handle stop session RPC request."""
        print("Handling stop session request")
        try:
            session_id = params.get("sessionId", "")

            success = self._stop_session(session_id)
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

    def _stop_session(self, session_id: str) -> bool:
        """Stop a session by session ID or PID."""
        print(f"Attempting to stop session {session_id}")

        # Try to find by session ID first
        for pid, session in self.tracked_sessions.items():
            if session.happy_session_id == session_id or (
                session_id.startswith("PID-")
                and pid == int(session_id.replace("PID-", ""))
            ):
                try:
                    # Send SIGTERM to the process
                    os.kill(pid, signal.SIGTERM)
                    print(f"Sent SIGTERM to session {session_id} (PID: {pid})")

                    # Remove from tracking
                    del self.tracked_sessions[pid]
                    print(f"Removed session {session_id} from tracking")
                    return True

                except ProcessLookupError:
                    # Process already dead
                    print(f"Process {pid} already dead, removing from tracking")
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

        self.tracked_sessions.clear()

        if self.sio.connected:
            await self.sio.disconnect()

        print("Daemon shutdown complete")
