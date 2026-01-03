"""PostToolUse hook input dataclass."""

import re
from dataclasses import dataclass, field
from typing import Any

from .BaseHookInput import BaseHookInput


@dataclass
class PostToolUseInput(BaseHookInput):
    """
    Input for PostToolUse hooks.

    Contains tool result information in addition to base fields.
    """

    tool_name: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_use_id: str = ""
    tool_result: str = ""
    tool_error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PostToolUseInput":
        """Create instance from raw JSON dict."""
        return cls(
            session_id=data.get("session_id", ""),
            cwd=data.get("cwd", ""),
            hook_event_name=data.get("hook_event_name", ""),
            transcript_path=data.get("transcript_path", ""),
            permission_mode=data.get("permission_mode", "default"),
            tool_name=data.get("tool_name", ""),
            tool_input=data.get("tool_input", {}),
            tool_use_id=data.get("tool_use_id", ""),
            tool_result=data.get("tool_result", ""),
            tool_error=data.get("tool_error"),
        )

    # -------------------------------------------------------------------------
    # Convenience properties
    # -------------------------------------------------------------------------

    @property
    def succeeded(self) -> bool:
        """True if tool completed without error."""
        return self.tool_error is None

    @property
    def failed(self) -> bool:
        """True if tool encountered an error."""
        return self.tool_error is not None

    @property
    def file_path(self) -> str | None:
        """Get file_path from tool_input (Write/Edit/Read tools)."""
        return self.tool_input.get("file_path")

    @property
    def content(self) -> str | None:
        """Get content from tool_input (Write tool)."""
        return self.tool_input.get("content")

    @property
    def command(self) -> str | None:
        """Get command from tool_input (Bash tool)."""
        return self.tool_input.get("command")

    # -------------------------------------------------------------------------
    # Helper methods for path matching
    # -------------------------------------------------------------------------

    def file_path_matches(self, *globs: str) -> bool:
        """
        Check if tool_input.file_path matches any of the provided glob patterns.

        See PreToolUseInput.file_path_matches for full documentation.
        """
        if not self.file_path:
            return False

        return self._matches_any_glob(self.file_path, globs)

    def file_path_excludes(self, *globs: str) -> bool:
        """
        Check if tool_input.file_path does NOT match any of the provided globs.

        See PreToolUseInput.file_path_excludes for full documentation.
        """
        if not self.file_path:
            return True

        return not self._matches_any_glob(self.file_path, globs)

    def _matches_any_glob(self, path: str, globs: tuple[str, ...]) -> bool:
        """Check if path matches any of the glob patterns."""
        for glob in globs:
            if self._matches_glob(path, glob):
                return True

        return False

    def _matches_glob(self, path: str, glob: str) -> bool:
        """Check if path matches a glob pattern."""
        regex = self._glob_to_regex(glob)
        return bool(re.match(regex, path))

    def _glob_to_regex(self, glob: str) -> str:
        """Convert a glob pattern to a regex pattern."""
        result = ""
        i = 0

        while i < len(glob):
            char = glob[i]

            if char == "*":
                if i + 1 < len(glob) and glob[i + 1] == "*":
                    result += ".*"
                    i += 2
                    if i < len(glob) and glob[i] == "/":
                        result += "/?"
                        i += 1
                else:
                    result += "[^/]*"
                    i += 1
            elif char == "?":
                result += "[^/]"
                i += 1
            elif char in r"\[](){}|^$+.":
                result += "\\" + char
                i += 1
            else:
                result += char
                i += 1

        return "^" + result + "$"
