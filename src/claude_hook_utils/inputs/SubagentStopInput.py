"""SubagentStop hook input dataclass."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .BaseHookInput import BaseHookInput


@dataclass
class SubagentStopInput(BaseHookInput):
    """
    Input for SubagentStop hooks.

    Fired when a subagent (Task tool) completes execution.

    Raw JSON example:
    ```json
    {
      "session_id": "...",
      "transcript_path": "~/.claude/projects/.../session.jsonl",
      "cwd": "/home/vscode/project",
      "permission_mode": "default",
      "hook_event_name": "SubagentStop",
      "stop_hook_active": false,
      "agent_id": "64fc4031",
      "agent_transcript_path": "~/.claude/projects/.../agent-64fc4031.jsonl"
    }
    ```

    The `stop_hook_active` field indicates whether a previous SubagentStop hook
    already blocked this agent and this is a retry after the agent attempted to
    address the feedback.
    """

    agent_id: str = ""
    agent_transcript_path: str = ""
    stop_hook_active: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SubagentStopInput":
        """Create instance from raw JSON dict."""
        return cls(
            session_id=data.get("session_id", ""),
            cwd=data.get("cwd", ""),
            hook_event_name=data.get("hook_event_name", ""),
            transcript_path=data.get("transcript_path", ""),
            permission_mode=data.get("permission_mode", "default"),
            agent_id=data.get("agent_id", ""),
            agent_transcript_path=data.get("agent_transcript_path", ""),
            stop_hook_active=data.get("stop_hook_active", False),
        )

    # -------------------------------------------------------------------------
    # Convenience properties
    # -------------------------------------------------------------------------

    @property
    def has_agent_id(self) -> bool:
        """Check if an agent ID was provided."""
        return bool(self.agent_id)

    @property
    def has_agent_transcript(self) -> bool:
        """Check if an agent transcript path was provided."""
        return bool(self.agent_transcript_path)

    @property
    def agent_transcript_path_expanded(self) -> Path | None:
        """Get the agent transcript path with ~ expanded."""
        if not self.agent_transcript_path:
            return None
        return Path(self.agent_transcript_path).expanduser()

    @property
    def agent_transcript_exists(self) -> bool:
        """Check if the agent transcript file exists."""
        path = self.agent_transcript_path_expanded
        return path is not None and path.exists()

    @property
    def is_retry(self) -> bool:
        """
        Check if this is a retry after a previous block.

        When stop_hook_active is True, this means the agent was blocked by a
        previous SubagentStop hook and has attempted to address the feedback.
        """
        return self.stop_hook_active

    @property
    def transcript_path_expanded(self) -> Path | None:
        """Get the session transcript path with ~ expanded."""
        if not self.transcript_path:
            return None
        return Path(self.transcript_path).expanduser()

    @property
    def transcript_exists(self) -> bool:
        """Check if the session transcript file exists."""
        path = self.transcript_path_expanded
        return path is not None and path.exists()

    @property
    def cwd_path(self) -> Path | None:
        """Get cwd as a Path object."""
        if not self.cwd:
            return None
        return Path(self.cwd)
