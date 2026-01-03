"""Base hook input dataclass with common fields."""

from dataclasses import dataclass
from typing import Any


@dataclass
class BaseHookInput:
    """
    Base class for all hook inputs.

    Contains fields common to all hook types.
    """

    session_id: str
    cwd: str
    hook_event_name: str
    transcript_path: str
    permission_mode: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaseHookInput":
        """
        Create instance from raw JSON dict.

        Subclasses should override this to handle their specific fields.
        """
        return cls(
            session_id=data.get("session_id", ""),
            cwd=data.get("cwd", ""),
            hook_event_name=data.get("hook_event_name", ""),
            transcript_path=data.get("transcript_path", ""),
            permission_mode=data.get("permission_mode", "default"),
        )
