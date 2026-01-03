"""
claude-hook-utils - Utilities for building Claude Code hooks.

This package provides a clean API for building Claude Code hooks with:
- Typed input dataclasses with helper methods
- Response builders with the correct output format
- A base handler class for dispatching multiple hook types
- Optional logging utilities

Quick Start:
    from claude_hook_utils import HookHandler, PreToolUseInput, PreToolUseResponse

    class MyValidator(HookHandler):
        def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
            if not input.file_path_matches('**/*.php'):
                return None
            return PreToolUseResponse.allow()

    if __name__ == "__main__":
        MyValidator().run()
"""

from .handler import HookHandler
from .inputs import BaseHookInput, PostToolUseInput, PreToolUseInput
from .logging import HookLogger
from .responses import BaseHookResponse, PostToolUseResponse, PreToolUseResponse

__version__ = "0.1.0"

__all__ = [
    # Handler
    "HookHandler",
    # Inputs
    "BaseHookInput",
    "PreToolUseInput",
    "PostToolUseInput",
    # Responses
    "BaseHookResponse",
    "PreToolUseResponse",
    "PostToolUseResponse",
    # Logging
    "HookLogger",
]
