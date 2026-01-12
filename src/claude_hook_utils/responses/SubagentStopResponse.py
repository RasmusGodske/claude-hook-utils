"""SubagentStop hook response class."""

from dataclasses import dataclass
from typing import Any, Literal

from .BaseHookResponse import BaseHookResponse


@dataclass
class SubagentStopResponse(BaseHookResponse):
    """
    Response for SubagentStop hooks.

    Use the static factory methods to create responses:
        SubagentStopResponse.allow()
        SubagentStopResponse.block("reason for feedback to agent")

    When blocked, the reason is sent back to the subagent as feedback,
    allowing it to address the issue and retry.
    """

    decision: Literal["allow", "block"]
    reason: str | None = None

    @staticmethod
    def allow(reason: str | None = None) -> "SubagentStopResponse":
        """
        Allow the subagent result to be accepted.

        In most cases, you can just return None from the handler instead.

        Args:
            reason: Optional internal reason (not sent to agent).

        Returns:
            SubagentStopResponse with allow decision.
        """
        return SubagentStopResponse(decision="allow", reason=reason)

    @staticmethod
    def block(reason: str) -> "SubagentStopResponse":
        """
        Block the subagent result and send feedback.

        The reason is sent back to the subagent, which can then attempt
        to address the feedback and retry. This is useful for code review
        hooks that want the agent to fix issues before accepting the result.

        Args:
            reason: Feedback message sent to the subagent.

        Returns:
            SubagentStopResponse with block decision.
        """
        return SubagentStopResponse(decision="block", reason=reason)

    def to_json(self) -> dict[str, Any]:
        """
        Convert to Claude Code output format.

        SubagentStop uses a simple format (not hookSpecificOutput):
        ```json
        {
          "decision": "block",
          "reason": "feedback message"
        }
        ```

        Returns:
            Dict with decision and optional reason.
        """
        if self.decision == "allow":
            # No output needed for allow - empty dict or no output both work
            return {}

        # Block decision requires the specific format
        return {
            "decision": "block",
            "reason": self.reason or "",
        }
