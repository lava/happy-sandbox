"""Session supervision module for monitoring and relaying Claude session messages to the server.

This module provides functionality to supervise running Claude sessions and forward
their messages to the Happy server, similar to how the happy-cli client works.
"""

import asyncio
import base64
import json
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from uuid import uuid4

import socketio
from pydantic import BaseModel, Field

from happy_sandbox.encryption import encrypt, decrypt


class SessionMessage(BaseModel):
    """A message from a Claude session."""

    role: str  # 'user', 'agent', etc.
    content: Dict[str, Any]
    meta: Optional[Dict[str, Any]] = None


class SessionEvent(BaseModel):
    """A session event."""

    type: str  # 'switch', 'message', 'permission-mode-changed', 'ready'
    mode: Optional[str] = None
    message: Optional[str] = None


class UsageData(BaseModel):
    """Token usage data from Claude."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


class SupervisedSession(BaseModel):
    """Information about a supervised Claude session."""

    session_id: str
    claude_session_id: Optional[str] = None
    directory: str
    pid: int
    thinking: bool = False
    mode: str = "local"  # 'local' or 'remote'
    last_keepalive: int = Field(default_factory=lambda: int(time.time() * 1000))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SessionSupervisor:
    """Supervises Claude sessions and forwards messages to the Happy server."""

    def __init__(
        self,
        server_url: str,
        machine_id: str,
        encryption_key: bytes,
        token: str,
        encryption_variant: str = "legacy",
    ):
        self.server_url = server_url
        self.machine_id = machine_id
        self.encryption_key = encryption_key
        self.token = token
        self.encryption_variant = encryption_variant

        # Session tracking
        self.supervised_sessions: Dict[str, SupervisedSession] = {}

        # Socket connection for session messages
        self.session_socket: Optional[socketio.AsyncClient] = None
        self.shutdown_requested = False

    async def start(self) -> None:
        """Start the session supervisor."""
        print("Starting session supervisor...")

        # Create separate socket connection for session messages
        self.session_socket = socketio.AsyncClient()

        # Setup socket handlers
        self._setup_session_socket_handlers()

        # Connect to server
        await self._connect_session_socket()

        # Start keepalive loop
        asyncio.create_task(self._keepalive_loop())

    async def stop(self) -> None:
        """Stop the session supervisor."""
        print("Stopping session supervisor...")
        self.shutdown_requested = True

        # Send session death messages for all supervised sessions
        for session in self.supervised_sessions.values():
            await self._send_session_death(session.session_id)

        # Disconnect socket
        if self.session_socket and self.session_socket.connected:
            await self.session_socket.disconnect()

    def _setup_session_socket_handlers(self) -> None:
        """Setup socket event handlers for session messages."""

        @self.session_socket.event
        async def connect():
            print("Session supervisor socket connected")

        @self.session_socket.event
        async def disconnect():
            print("Session supervisor socket disconnected")

        @self.session_socket.event
        async def connect_error(data):
            print(f"Session supervisor socket connection error: {data}")

        @self.session_socket.on('update')
        async def update(data: Dict[str, Any]):
            """Handle update events from server."""
            try:
                body = data.get('body', {})
                if body.get('t') == 'new-message':
                    # Decrypt and forward user messages to appropriate session
                    await self._handle_incoming_user_message(data)
            except Exception as e:
                print(f"Error handling session update: {e}")

    async def _connect_session_socket(self) -> None:
        """Connect the session socket to the server."""
        ws_url = self.server_url.replace("http://", "ws://").replace("https://", "wss://")

        # Note: This connects as a machine-scoped client, but we'll need to handle
        # session-specific authentication differently in production
        await self.session_socket.connect(
            ws_url,
            auth={
                "token": self.token,
                "clientType": "machine-scoped",  # May need session-scoped per session
                "machineId": self.machine_id,
            },
            socketio_path="/v1/updates",
            transports=["websocket"],
        )

    async def supervise_session(
        self,
        session_id: str,
        claude_session_id: Optional[str],
        directory: str,
        pid: int
    ) -> SupervisedSession:
        """Start supervising a Claude session."""
        print(f"Starting supervision for session {session_id} (PID: {pid})")

        session = SupervisedSession(
            session_id=session_id,
            claude_session_id=claude_session_id,
            directory=directory,
            pid=pid,
        )

        self.supervised_sessions[session_id] = session

        # Send initial session ready event
        await self._send_session_event(session_id, SessionEvent(type="ready"))

        return session

    async def unsupervise_session(self, session_id: str) -> None:
        """Stop supervising a Claude session."""
        if session_id not in self.supervised_sessions:
            return

        print(f"Stopping supervision for session {session_id}")

        # Send session death message
        await self._send_session_death(session_id)

        # Remove from tracking
        del self.supervised_sessions[session_id]

    async def send_claude_message(
        self,
        session_id: str,
        message_data: Dict[str, Any]
    ) -> None:
        """Send a Claude session message to the server."""
        if session_id not in self.supervised_sessions:
            print(f"Warning: Session {session_id} not supervised")
            return

        try:
            # Determine message content based on message type
            content = self._format_message_content(message_data)

            # Encrypt and send
            encrypted_content = base64.b64encode(
                encrypt(self.encryption_key, self.encryption_variant, content)
            ).decode("ascii")

            print(f"DEBUG: Sending Claude session message to server - session_id: {session_id}, type: {message_data.get('type')}")
            await self.session_socket.emit('message', {
                'sid': session_id,
                'message': encrypted_content
            })

            # Track usage if present
            if message_data.get('type') == 'assistant' and 'usage' in message_data.get('message', {}):
                await self._send_usage_data(session_id, message_data['message']['usage'])

            # Update metadata if summary message
            if message_data.get('type') == 'summary':
                await self._update_session_metadata(session_id, {
                    'summary': {
                        'text': message_data.get('summary', ''),
                        'updatedAt': int(time.time() * 1000)
                    }
                })

        except Exception as e:
            print(f"Error sending Claude message for session {session_id}: {e}")

    def _format_message_content(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format message data into the expected content structure."""
        msg_type = message_data.get('type')

        if msg_type == 'user' and isinstance(message_data.get('message', {}).get('content'), str):
            # User text message
            return {
                'role': 'user',
                'content': {
                    'type': 'text',
                    'text': message_data['message']['content']
                },
                'meta': {
                    'sentFrom': 'daemon'
                }
            }
        else:
            # Agent message (Claude output, codex, etc.)
            return {
                'role': 'agent',
                'content': {
                    'type': 'output',
                    'data': message_data
                },
                'meta': {
                    'sentFrom': 'daemon'
                }
            }

    async def send_codex_message(
        self,
        session_id: str,
        message_data: Dict[str, Any]
    ) -> None:
        """Send a Codex message to the server."""
        if session_id not in self.supervised_sessions:
            print(f"Warning: Session {session_id} not supervised")
            return

        try:
            content = {
                'role': 'agent',
                'content': {
                    'type': 'codex',
                    'data': message_data
                },
                'meta': {
                    'sentFrom': 'daemon'
                }
            }

            encrypted_content = base64.b64encode(
                encrypt(self.encryption_key, self.encryption_variant, content)
            ).decode("ascii")

            print(f"DEBUG: Sending Codex session message to server - session_id: {session_id}")
            await self.session_socket.emit('message', {
                'sid': session_id,
                'message': encrypted_content
            })

        except Exception as e:
            print(f"Error sending Codex message for session {session_id}: {e}")

    async def send_session_event(
        self,
        session_id: str,
        event_type: str,
        **kwargs
    ) -> None:
        """Send a session event."""
        event = SessionEvent(type=event_type, **kwargs)
        await self._send_session_event(session_id, event)

    async def _send_session_event(
        self,
        session_id: str,
        event: SessionEvent,
        event_id: Optional[str] = None
    ) -> None:
        """Send a session event to the server."""
        if session_id not in self.supervised_sessions:
            return

        try:
            content = {
                'role': 'agent',
                'content': {
                    'id': event_id or str(uuid4()),
                    'type': 'event',
                    'data': event.model_dump()
                }
            }

            encrypted_content = base64.b64encode(
                encrypt(self.encryption_key, self.encryption_variant, content)
            ).decode("ascii")

            print(f"DEBUG: Sending session event to server - session_id: {session_id}, event_type: {event.type}")
            await self.session_socket.emit('message', {
                'sid': session_id,
                'message': encrypted_content
            })

        except Exception as e:
            print(f"Error sending session event for session {session_id}: {e}")

    async def update_session_thinking(self, session_id: str, thinking: bool) -> None:
        """Update the thinking state of a session."""
        if session_id in self.supervised_sessions:
            self.supervised_sessions[session_id].thinking = thinking

    async def update_session_mode(self, session_id: str, mode: str) -> None:
        """Update the mode of a session."""
        if session_id in self.supervised_sessions:
            old_mode = self.supervised_sessions[session_id].mode
            self.supervised_sessions[session_id].mode = mode

            if old_mode != mode:
                await self.send_session_event(session_id, "switch", mode=mode)

    async def update_session_claude_id(self, session_id: str, claude_session_id: str) -> None:
        """Update the Claude session ID for a session."""
        if session_id in self.supervised_sessions:
            self.supervised_sessions[session_id].claude_session_id = claude_session_id
            await self._update_session_metadata(session_id, {
                'claudeSessionId': claude_session_id
            })

    async def _update_session_metadata(self, session_id: str, metadata_update: Dict[str, Any]) -> None:
        """Update session metadata (placeholder - would need session-specific metadata handling)."""
        if session_id in self.supervised_sessions:
            self.supervised_sessions[session_id].metadata.update(metadata_update)

    async def _send_usage_data(self, session_id: str, usage: Dict[str, Any]) -> None:
        """Send usage data to the server."""
        try:
            total_tokens = (
                usage.get('input_tokens', 0) +
                usage.get('output_tokens', 0) +
                usage.get('cache_creation_input_tokens', 0) +
                usage.get('cache_read_input_tokens', 0)
            )

            usage_report = {
                'key': 'claude-session',
                'sessionId': session_id,
                'tokens': {
                    'total': total_tokens,
                    'input': usage.get('input_tokens', 0),
                    'output': usage.get('output_tokens', 0),
                    'cache_creation': usage.get('cache_creation_input_tokens', 0),
                    'cache_read': usage.get('cache_read_input_tokens', 0)
                },
                'cost': {
                    'total': 0,  # TODO: Calculate actual costs
                    'input': 0,
                    'output': 0
                }
            }

            print(f"DEBUG: Sending usage report to server - session_id: {session_id}, total_tokens: {total_tokens}")
            await self.session_socket.emit('usage-report', usage_report)

        except Exception as e:
            print(f"Error sending usage data for session {session_id}: {e}")

    async def _send_session_death(self, session_id: str) -> None:
        """Send session death message."""
        try:
            print(f"DEBUG: Sending session death message to server - session_id: {session_id}")
            await self.session_socket.emit('session-end', {
                'sid': session_id,
                'time': int(time.time() * 1000)
            })
        except Exception as e:
            print(f"Error sending session death for session {session_id}: {e}")

    async def _send_keepalive(self, session_id: str, thinking: bool, mode: str) -> None:
        """Send keep-alive message for a session."""
        try:
            # In python-socketio, there's no .volatile method like in JavaScript
            # Just send the keepalive normally
            print(f"DEBUG: Sending session keepalive to server - session_id: {session_id}, thinking: {thinking}, mode: {mode}")
            await self.session_socket.emit('session-alive', {
                'sid': session_id,
                'time': int(time.time() * 1000),
                'thinking': thinking,
                'mode': mode
            })
        except Exception as e:
            print(f"Error sending keepalive for session {session_id}: {e}")

    async def _keepalive_loop(self) -> None:
        """Periodic keep-alive loop for all supervised sessions."""
        while not self.shutdown_requested:
            try:
                current_time = int(time.time() * 1000)

                for session in self.supervised_sessions.values():
                    # Send keep-alive every 2 seconds (like happy-cli)
                    if current_time - session.last_keepalive >= 2000:
                        await self._send_keepalive(
                            session.session_id,
                            session.thinking,
                            session.mode
                        )
                        session.last_keepalive = current_time

                await asyncio.sleep(1)  # Check every second

            except Exception as e:
                print(f"Keepalive loop error: {e}")
                await asyncio.sleep(5)

    async def _handle_incoming_user_message(self, data: Dict[str, Any]) -> None:
        """Handle incoming user messages from the server."""
        # This would forward user messages to the appropriate Claude session
        # Implementation depends on how sessions communicate with the supervisor
        pass

    def get_supervised_sessions(self) -> Dict[str, SupervisedSession]:
        """Get all currently supervised sessions."""
        return self.supervised_sessions.copy()