"""SubagentStart hook response class."""

from dataclasses import dataclass
from typing import Any

from .BaseHookResponse import BaseHookResponse


@dataclass
class SubagentStartResponse(BaseHookResponse):
    """
    Response for SubagentStart hooks.

    SubagentStart hooks typically just track state and don't need to output
    a response. Returning None from the handler is the most common case.

    Use the static factory methods to create responses if needed:
        SubagentStartResponse.allow()
    """

    @staticmethod
    def allow() -> "SubagentStartResponse":
        """
        Allow the subagent to start.

        In most cases, you can just return None from the handler instead.

        Returns:
            SubagentStartResponse allowing the subagent to start.
        """
        return SubagentStartResponse()

    def to_json(self) -> dict[str, Any]:
        """
        Convert to Claude Code output format.

        SubagentStart hooks don't require a specific output format.
        Returning an empty dict signals "allow" without any special handling.

        Returns:
            Empty dict (no output needed to allow).
        """
        return {}
