"""SubagentStart hook input dataclass."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .BaseHookInput import BaseHookInput


@dataclass
class SubagentStartInput(BaseHookInput):
    """
    Input for SubagentStart hooks.

    Fired when a subagent (Task tool) begins execution.

    Raw JSON example:
    ```json
    {
      "session_id": "...",
      "transcript_path": "~/.claude/projects/.../session.jsonl",
      "cwd": "/home/vscode/project",
      "hook_event_name": "SubagentStart",
      "agent_id": "64fc4031",
      "agent_type": "backend-engineer"
    }
    ```
    """

    agent_id: str = ""
    agent_type: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SubagentStartInput":
        """Create instance from raw JSON dict."""
        return cls(
            session_id=data.get("session_id", ""),
            cwd=data.get("cwd", ""),
            hook_event_name=data.get("hook_event_name", ""),
            transcript_path=data.get("transcript_path", ""),
            permission_mode=data.get("permission_mode", "default"),
            agent_id=data.get("agent_id", ""),
            agent_type=data.get("agent_type", ""),
        )

    # -------------------------------------------------------------------------
    # Convenience properties
    # -------------------------------------------------------------------------

    @property
    def has_agent_id(self) -> bool:
        """Check if an agent ID was provided."""
        return bool(self.agent_id)

    @property
    def has_agent_type(self) -> bool:
        """Check if an agent type was provided."""
        return bool(self.agent_type)

    @property
    def transcript_path_expanded(self) -> Path | None:
        """Get the transcript path with ~ expanded."""
        if not self.transcript_path:
            return None
        return Path(self.transcript_path).expanduser()

    @property
    def transcript_exists(self) -> bool:
        """Check if the transcript file exists."""
        path = self.transcript_path_expanded
        return path is not None and path.exists()

    @property
    def cwd_path(self) -> Path | None:
        """Get cwd as a Path object."""
        if not self.cwd:
            return None
        return Path(self.cwd)
