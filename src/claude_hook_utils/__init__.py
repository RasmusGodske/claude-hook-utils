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

Subagent Hooks:
    from claude_hook_utils import HookHandler, SubagentStopInput, SubagentStopResponse

    class SubagentReviewer(HookHandler):
        def subagent_stop(self, input: SubagentStopInput) -> SubagentStopResponse | None:
            # Review agent output...
            if issues_found:
                return SubagentStopResponse.block("Please fix: ...")
            return SubagentStopResponse.allow()

    if __name__ == "__main__":
        SubagentReviewer().run()
"""

from .handler import HookHandler
from .inputs import (
    BaseHookInput,
    PostToolUseInput,
    PreToolUseInput,
    SubagentStartInput,
    SubagentStopInput,
)
from .logging import HookLogger
from .responses import (
    BaseHookResponse,
    PostToolUseResponse,
    PreToolUseResponse,
    SubagentStartResponse,
    SubagentStopResponse,
)

__version__ = "0.4.0"

__all__ = [
    # Handler
    "HookHandler",
    # Inputs
    "BaseHookInput",
    "PreToolUseInput",
    "PostToolUseInput",
    "SubagentStartInput",
    "SubagentStopInput",
    # Responses
    "BaseHookResponse",
    "PreToolUseResponse",
    "PostToolUseResponse",
    "SubagentStartResponse",
    "SubagentStopResponse",
    # Logging
    "HookLogger",
]
