"""Base hook handler class."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from ..inputs import PostToolUseInput, PreToolUseInput
from ..logging import HookLogger
from ..responses import BaseHookResponse, PostToolUseResponse, PreToolUseResponse

if TYPE_CHECKING:
    pass


class HookHandler:
    """
    Base class for handling Claude Code hooks.

    Extend this class and override the hooks you need:

        class MyValidator(HookHandler):
            def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
                if not input.file_path_matches('**/*.php'):
                    return None  # Skip
                # ... validation logic ...
                return PreToolUseResponse.allow()

        if __name__ == "__main__":
            MyValidator().run()

    With logging enabled (writes to .claude/logs/hooks.jsonl):

        class MyValidator(HookHandler):
            def __init__(self) -> None:
                super().__init__(
                    logger=HookLogger.create_default("MyValidator")
                )

        if __name__ == "__main__":
            MyValidator().run()

    A single handler can process multiple hook types. The run() method
    reads from stdin, determines the hook type, and dispatches to the
    appropriate method. The logger automatically receives session_id
    context when input is processed.
    """

    def __init__(self, logger: HookLogger | None = None) -> None:
        """
        Initialize the hook handler.

        Args:
            logger: Optional HookLogger for logging decisions and events.
                    Use HookLogger.create_default("HookName") for easy setup.
        """
        self._logger = logger

    @property
    def logger(self) -> HookLogger | None:
        """Get the logger instance (with session context if available)."""
        return self._logger

    # -------------------------------------------------------------------------
    # Hook methods to override
    # -------------------------------------------------------------------------

    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        """
        Handle PreToolUse hook.

        Override this method to validate tool calls before they execute.

        Args:
            input: The PreToolUse input containing tool_name, tool_input, etc.

        Returns:
            PreToolUseResponse to allow/deny/ask, or None to skip (allow).
        """
        return None

    def post_tool_use(self, input: PostToolUseInput) -> PostToolUseResponse | None:
        """
        Handle PostToolUse hook.

        Override this method to react to tool results after execution.

        Args:
            input: The PostToolUse input containing tool_result, tool_error, etc.

        Returns:
            PostToolUseResponse to acknowledge or add context, or None to skip.
        """
        return None

    # -------------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------------

    def run(self) -> int:
        """
        Run the hook handler.

        Reads JSON from stdin, dispatches to the appropriate handler method,
        and outputs the response to stdout.

        Returns:
            Exit code (0 for success).
        """
        try:
            raw_input = self._read_stdin()
        except json.JSONDecodeError as e:
            self._log_error(f"Invalid JSON input: {e}")
            return 0  # Fail open

        if raw_input is None:
            return 0  # No input, skip

        # Update logger with session context from input
        self._update_logger_context(raw_input)

        hook_event_name = raw_input.get("hook_event_name", "")

        # Log hook invocation
        self._log_hook_invocation(hook_event_name, raw_input)

        response = self._dispatch(hook_event_name, raw_input)

        # Log hook response
        self._log_hook_response(hook_event_name, raw_input, response)

        if response is not None:
            self._write_response(response)

        return 0

    # -------------------------------------------------------------------------
    # Internal methods
    # -------------------------------------------------------------------------

    def _read_stdin(self) -> dict | None:
        """Read and parse JSON from stdin."""
        if sys.stdin.isatty():
            return None

        content = sys.stdin.read().strip()
        if not content:
            return None

        return json.loads(content)

    def _update_logger_context(self, raw_input: dict) -> None:
        """Update logger with session context from input."""
        if not self._logger:
            return

        session_id = raw_input.get("session_id")
        cwd = raw_input.get("cwd")

        # Always reconfigure logger with project cwd if available.
        # This is necessary because hooks run in their own directory
        # (via cd $PLUGIN_ROOT/hooks/HookName), but logs should go to
        # the project's .claude/logs/ directory.
        if cwd:
            self._logger = HookLogger.create_default(
                hook_name=self._logger._hook_name,
                namespace=self._logger._namespace,
                session_id=session_id or self._logger._session_id,
                cwd=cwd,
            )
        elif session_id and not self._logger._session_id:
            # Just add session_id if no cwd but we have session
            self._logger = self._logger.with_session(session_id)

    def _dispatch(self, hook_event_name: str, raw_input: dict) -> BaseHookResponse | None:
        """Dispatch to the appropriate handler based on hook type."""
        match hook_event_name:
            case "PreToolUse":
                input_obj = PreToolUseInput.from_dict(raw_input)
                return self.pre_tool_use(input_obj)

            case "PostToolUse":
                input_obj = PostToolUseInput.from_dict(raw_input)
                return self.post_tool_use(input_obj)

            case _:
                self._log_error(f"Unknown hook event: {hook_event_name}")
                return None

    def _write_response(self, response: BaseHookResponse) -> None:
        """Write response JSON to stdout."""
        json_output = response.to_json()
        print(json.dumps(json_output))

    def _log_error(self, message: str) -> None:
        """Log an error message."""
        if self._logger:
            self._logger.error(message)
        else:
            print(f"[HookHandler] {message}", file=sys.stderr)

    def _log_hook_invocation(self, hook_event_name: str, raw_input: dict) -> None:
        """Log when a hook is invoked."""
        if not self._logger:
            return

        # Extract key context from input
        tool_name = raw_input.get("tool_name", "unknown")
        tool_input = raw_input.get("tool_input", {})

        # Extract relevant info based on tool type
        context: dict = {
            "tool_name": tool_name,
        }

        # Add file_path if present
        if "file_path" in tool_input:
            context["file_path"] = tool_input["file_path"]

        # Add command if present (for Bash)
        if "command" in tool_input:
            # Truncate long commands
            command = tool_input["command"]
            context["command"] = command[:200] + "..." if len(command) > 200 else command

        self._logger.info(f"Hook invoked: {hook_event_name}", **context)

    def _log_hook_response(
        self,
        hook_event_name: str,
        raw_input: dict,
        response: BaseHookResponse | None,
    ) -> None:
        """Log the hook response."""
        if not self._logger:
            return

        tool_name = raw_input.get("tool_name", "unknown")

        if response is None:
            self._logger.decision(
                decision="skip",
                reason="No opinion (returned None)",
                tool_name=tool_name,
            )
            return

        # Get the response JSON to extract decision info
        response_json = response.to_json()
        hook_output = response_json.get("hookSpecificOutput", {})
        permission_decision = hook_output.get("permissionDecision", "unknown")
        reason = hook_output.get("permissionDecisionReason")

        self._logger.decision(
            decision=permission_decision,
            reason=reason,
            tool_name=tool_name,
        )
