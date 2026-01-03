"""Base hook response class."""

from abc import ABC, abstractmethod
from typing import Any


class BaseHookResponse(ABC):
    """
    Abstract base class for all hook responses.

    Subclasses must implement to_json() to produce the hookSpecificOutput format.
    """

    @abstractmethod
    def to_json(self) -> dict[str, Any]:
        """
        Convert response to Claude Code hookSpecificOutput format.

        Returns:
            Dict with 'hookSpecificOutput' key containing the response.
        """
        pass
