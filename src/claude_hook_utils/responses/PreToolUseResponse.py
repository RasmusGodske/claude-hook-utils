"""PreToolUse hook response class."""

from dataclasses import dataclass, field
from typing import Any, Literal

from .BaseHookResponse import BaseHookResponse


@dataclass
class PreToolUseResponse(BaseHookResponse):
    """
    Response for PreToolUse hooks.

    Use the static factory methods to create responses:
        PreToolUseResponse.allow()
        PreToolUseResponse.deny("reason")
        PreToolUseResponse.ask("reason")

    Use with_updated_input() to modify tool parameters (only with allow):
        PreToolUseResponse.allow().with_updated_input(file_path="/new/path")
    """

    decision: Literal["allow", "deny", "ask"]
    reason: str | None = None
    updated_input: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def allow(reason: str | None = None) -> "PreToolUseResponse":
        """
        Allow the tool to execute.

        Args:
            reason: Optional reason shown to user (not Claude).

        Returns:
            PreToolUseResponse with allow decision.
        """
        return PreToolUseResponse(decision="allow", reason=reason)

    @staticmethod
    def deny(reason: str) -> "PreToolUseResponse":
        """
        Block the tool execution.

        The reason is shown to Claude as feedback, allowing it to adapt
        its approach (e.g., try a different file path, fix content issues).

        Args:
            reason: Explanation of why the tool was blocked.

        Returns:
            PreToolUseResponse with deny decision.
        """
        return PreToolUseResponse(decision="deny", reason=reason)

    @staticmethod
    def ask(reason: str) -> "PreToolUseResponse":
        """
        Request user confirmation before proceeding.

        The reason is shown in the confirmation dialog.

        Args:
            reason: Explanation shown in confirmation dialog.

        Returns:
            PreToolUseResponse with ask decision.
        """
        return PreToolUseResponse(decision="ask", reason=reason)

    def with_updated_input(self, **updates: Any) -> "PreToolUseResponse":
        """
        Modify tool_input before execution.

        Only valid with 'allow' decision. The updates are merged with
        the original tool_input.

        Example:
            PreToolUseResponse.allow("Auto-corrected path").with_updated_input(
                file_path="/corrected/path.php"
            )

        Args:
            **updates: Key-value pairs to update in tool_input.

        Returns:
            Self with updated_input set.

        Raises:
            ValueError: If used with deny or ask decision.
        """
        if self.decision != "allow":
            raise ValueError("with_updated_input() can only be used with allow()")

        self.updated_input = updates
        return self

    def to_json(self) -> dict[str, Any]:
        """
        Convert to Claude Code hookSpecificOutput format.

        Returns:
            Dict with 'hookSpecificOutput' containing the response.
        """
        output: dict[str, Any] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": self.decision,
        }

        if self.reason:
            output["permissionDecisionReason"] = self.reason

        if self.updated_input:
            output["updatedInput"] = self.updated_input

        return {"hookSpecificOutput": output}
