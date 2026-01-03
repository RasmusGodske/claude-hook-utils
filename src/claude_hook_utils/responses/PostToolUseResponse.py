"""PostToolUse hook response class."""

from dataclasses import dataclass
from typing import Any

from .BaseHookResponse import BaseHookResponse


@dataclass
class PostToolUseResponse(BaseHookResponse):
    """
    Response for PostToolUse hooks.

    PostToolUse hooks run after the tool has completed, so they cannot
    block or modify the tool call. They can only acknowledge or add
    system messages.

    Use the static factory methods to create responses:
        PostToolUseResponse.acknowledge()
        PostToolUseResponse.with_message("Warning message")
    """

    system_message: str | None = None

    @staticmethod
    def acknowledge() -> "PostToolUseResponse":
        """
        Acknowledge the tool result without any action.

        Returns:
            PostToolUseResponse with no message.
        """
        return PostToolUseResponse()

    @staticmethod
    def with_message(message: str) -> "PostToolUseResponse":
        """
        Acknowledge with a system message shown to the user.

        Args:
            message: Message to display to the user.

        Returns:
            PostToolUseResponse with system message.
        """
        return PostToolUseResponse(system_message=message)

    def to_json(self) -> dict[str, Any]:
        """
        Convert to Claude Code hookSpecificOutput format.

        Returns:
            Dict with 'hookSpecificOutput' containing the response.
        """
        output: dict[str, Any] = {
            "hookEventName": "PostToolUse",
        }

        if self.system_message:
            output["systemMessage"] = self.system_message

        return {"hookSpecificOutput": output}
