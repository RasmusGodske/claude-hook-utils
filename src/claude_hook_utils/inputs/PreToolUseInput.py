"""PreToolUse hook input dataclass."""

import re
from dataclasses import dataclass, field
from typing import Any

from .BaseHookInput import BaseHookInput


@dataclass
class PreToolUseInput(BaseHookInput):
    """
    Input for PreToolUse hooks.

    Contains tool-specific information in addition to base fields.
    """

    tool_name: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_use_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PreToolUseInput":
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
        )

    # -------------------------------------------------------------------------
    # Convenience properties for common tool_input fields
    # -------------------------------------------------------------------------

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

    @property
    def old_string(self) -> str | None:
        """Get old_string from tool_input (Edit tool)."""
        return self.tool_input.get("old_string")

    @property
    def new_string(self) -> str | None:
        """Get new_string from tool_input (Edit tool)."""
        return self.tool_input.get("new_string")

    @property
    def pattern(self) -> str | None:
        """Get pattern from tool_input (Glob/Grep tools)."""
        return self.tool_input.get("pattern")

    @property
    def url(self) -> str | None:
        """Get url from tool_input (WebFetch tool)."""
        return self.tool_input.get("url")

    @property
    def query(self) -> str | None:
        """Get query from tool_input (WebSearch tool)."""
        return self.tool_input.get("query")

    # -------------------------------------------------------------------------
    # Helper methods for path matching
    # -------------------------------------------------------------------------

    def file_path_matches(self, *globs: str) -> bool:
        """
        Check if tool_input.file_path matches any of the provided glob patterns.

        Uses glob-style patterns:
        - * matches any characters except /
        - ** matches any characters including / (recursive)
        - ? matches single character

        Examples:
            input.file_path_matches('**/*.php')
            input.file_path_matches('**/app/Data/**/*.php', '**/app/Models/**/*.php')

        Args:
            *globs: One or more glob patterns to match against

        Returns:
            True if file_path matches any pattern, False otherwise.
            Returns False if file_path is not present in tool_input.
        """
        if not self.file_path:
            return False

        return self._matches_any_glob(self.file_path, globs)

    def file_path_excludes(self, *globs: str) -> bool:
        """
        Check if tool_input.file_path does NOT match any of the provided globs.

        Useful for "skip unless" patterns:
            if input.file_path_excludes('**/app/**'):
                return None  # Skip - not in app directory

        Args:
            *globs: One or more glob patterns to check against

        Returns:
            True if file_path does NOT match any pattern.
            Returns True if file_path is not present in tool_input.
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
        """
        Check if path matches a glob pattern.

        Converts glob pattern to regex for reliable matching:
        - ** matches any characters including /
        - * matches any characters except /
        - ? matches single character
        """
        regex = self._glob_to_regex(glob)
        return bool(re.match(regex, path))

    def _glob_to_regex(self, glob: str) -> str:
        """
        Convert a glob pattern to a regex pattern.

        Handles:
        - ** -> matches any path segments (including /)
        - * -> matches any characters except /
        - ? -> matches single character except /
        - Other special chars are escaped
        """
        # Escape special regex characters (except * and ?)
        result = ""
        i = 0

        while i < len(glob):
            char = glob[i]

            if char == "*":
                # Check for **
                if i + 1 < len(glob) and glob[i + 1] == "*":
                    # ** matches any characters including /
                    result += ".*"
                    i += 2
                    # Skip trailing / after **
                    if i < len(glob) and glob[i] == "/":
                        result += "/?"
                        i += 1
                else:
                    # * matches any characters except /
                    result += "[^/]*"
                    i += 1
            elif char == "?":
                # ? matches single character except /
                result += "[^/]"
                i += 1
            elif char in r"\[](){}|^$+.":
                # Escape special regex characters
                result += "\\" + char
                i += 1
            else:
                result += char
                i += 1

        # Pattern should match the full path (anchored)
        return "^" + result + "$"
