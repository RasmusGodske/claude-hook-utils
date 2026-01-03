"""Hook input dataclasses."""

from .BaseHookInput import BaseHookInput
from .PostToolUseInput import PostToolUseInput
from .PreToolUseInput import PreToolUseInput

__all__ = [
    "BaseHookInput",
    "PreToolUseInput",
    "PostToolUseInput",
]
