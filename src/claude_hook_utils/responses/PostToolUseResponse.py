"""PostToolUse hook response class."""

from dataclasses import dataclass
from typing import Any

from .BaseHookResponse import BaseHookResponse


@dataclass
class PostToolUseResponse(BaseHookResponse):
    """
    Response for PostToolUse hooks.

    PostToolUse hooks run after the tool has completed, so they cannot
    block or modify the tool call. They can only acknowledge or provide
    additional context to Claude.

    Use the static factory methods to create responses:
        PostToolUseResponse.acknowledge()
        PostToolUseResponse.with_context("Additional context for Claude")
    """

    additional_context: str | None = None

    @staticmethod
    def acknowledge() -> "PostToolUseResponse":
        """
        Acknowledge the tool result without any action.

        Returns:
            PostToolUseResponse with no additional context.
        """
        return PostToolUseResponse()

    @staticmethod
    def with_context(context: str) -> "PostToolUseResponse":
        """
        Acknowledge with additional context provided to Claude.

        The context is added to Claude's understanding but not directly
        displayed to the user.

        Args:
            context: Additional context for Claude to consider.

        Returns:
            PostToolUseResponse with additional context.
        """
        return PostToolUseResponse(additional_context=context)

    @staticmethod
    def with_message(message: str) -> "PostToolUseResponse":
        """
        Alias for with_context() for backwards compatibility.

        Deprecated: Use with_context() instead.

        Args:
            message: Additional context for Claude to consider.

        Returns:
            PostToolUseResponse with additional context.
        """
        return PostToolUseResponse(additional_context=message)

    def to_json(self) -> dict[str, Any]:
        """
        Convert to Claude Code hookSpecificOutput format.

        Returns:
            Dict with 'hookSpecificOutput' containing the response.
        """
        output: dict[str, Any] = {
            "hookEventName": "PostToolUse",
        }

        if self.additional_context:
            output["additionalContext"] = self.additional_context

        return {"hookSpecificOutput": output}
