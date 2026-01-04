"""Hook logger with JSONL output for easy debugging."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class HookLogger:
    """
    JSONL file-based logger for hook handlers.

    Writes structured JSON lines to a log file for easy debugging and analysis.
    Each log entry includes timestamp, session ID, hook name, and context.

    Log entries have two key fields for filtering:
    - level: Severity (debug, info, warning, error)
    - type: Entry type (invocation, response, debug)

    Example:
        # Simple setup with defaults (writes to .claude/logs/hooks.jsonl)
        logger = HookLogger.create_default("MyValidator")

        # With session context
        logger = HookLogger.create_default("MyValidator", session_id=input.session_id)

        # Usage
        logger.info("Processing file", file_path="/path/to/file.php")
        logger.invocation("PreToolUse", tool_name="Write", file_path="/path")
        logger.response("PreToolUse", "allow", raw_response={...}, tool_name="Write")

    Log format (JSONL - one JSON object per line):
        {"ts": "...", "level": "info", "type": "invocation", "hook": "MyValidator",
         "hook_event": "PreToolUse", "tool_name": "Write", ...}
    """

    DEFAULT_LOG_DIR = ".claude/logs"
    DEFAULT_LOG_FILE = "hooks.jsonl"

    def __init__(
        self,
        hook_name: str,
        session_id: str | None = None,
        log_file: str | Path | None = None,
        namespace: str | None = None,
    ) -> None:
        """
        Initialize the logger.

        Args:
            hook_name: Name of the hook (included in every log entry).
            session_id: Session ID (included in every log entry if provided).
            log_file: Path to log file. If None, logging is disabled.
            namespace: Optional namespace (included in log entries if provided).
        """
        self._hook_name = hook_name
        self._session_id = session_id
        self._log_file = Path(log_file) if log_file else None
        self._namespace = namespace
        self._start_time: float | None = None

    @classmethod
    def create_default(
        cls,
        hook_name: str,
        namespace: str | None = None,
        session_id: str | None = None,
        cwd: str | None = None,
    ) -> HookLogger:
        """
        Create a logger with default settings.

        Writes to .claude/logs/{namespace}/hooks.jsonl in the working directory.
        If no namespace is provided, writes to .claude/logs/hooks.jsonl.

        The log directory can be overridden with CLAUDE_HOOK_LOG_DIR env var.
        The namespace can be overridden with CLAUDE_HOOK_LOG_NAMESPACE env var.

        Args:
            hook_name: Name of the hook (included in every log entry).
            namespace: Plugin/project namespace for log subdirectory (e.g., "claude-liv-conventions").
            session_id: Session ID (included in every log entry if provided).
            cwd: Working directory. Defaults to current directory.

        Returns:
            Configured HookLogger instance.
        """
        # Allow env var overrides
        log_dir = os.environ.get("CLAUDE_HOOK_LOG_DIR")
        namespace = os.environ.get("CLAUDE_HOOK_LOG_NAMESPACE", namespace)

        if log_dir:
            # If explicit log dir is set, use it directly
            log_path = Path(log_dir) / cls.DEFAULT_LOG_FILE
        else:
            base_dir = Path(cwd) if cwd else Path.cwd()
            if namespace:
                log_path = base_dir / cls.DEFAULT_LOG_DIR / namespace / cls.DEFAULT_LOG_FILE
            else:
                log_path = base_dir / cls.DEFAULT_LOG_DIR / cls.DEFAULT_LOG_FILE

        return cls(
            hook_name=hook_name,
            session_id=session_id,
            log_file=log_path,
            namespace=namespace,
        )

    @staticmethod
    def null() -> HookLogger:
        """
        Create a no-op logger that discards all output.

        Useful as a default when no logging is desired.
        """
        return _NullLogger()

    def with_session(self, session_id: str) -> HookLogger:
        """
        Return a new logger with the session ID set.

        Useful when session_id is not known at logger creation time.

        Args:
            session_id: The session ID to include in log entries.

        Returns:
            New HookLogger with session_id set.
        """
        return HookLogger(
            hook_name=self._hook_name,
            session_id=session_id,
            log_file=self._log_file,
            namespace=self._namespace,
        )

    # -------------------------------------------------------------------------
    # Timing methods
    # -------------------------------------------------------------------------

    def start_timer(self) -> float:
        """
        Start a timer and return the start time.

        Returns:
            Start time as float (from time.perf_counter()).
        """
        self._start_time = time.perf_counter()
        return self._start_time

    def elapsed(self, start: float | None = None) -> float:
        """
        Get elapsed time since start.

        Args:
            start: Start time from start_timer(). If None, uses last start_timer() call.

        Returns:
            Elapsed time in seconds.
        """
        start_time = start or self._start_time or time.perf_counter()
        return time.perf_counter() - start_time

    def elapsed_ms(self, start: float | None = None) -> float:
        """
        Get elapsed time in milliseconds.

        Args:
            start: Start time from start_timer(). If None, uses last start_timer() call.

        Returns:
            Elapsed time in milliseconds.
        """
        return self.elapsed(start) * 1000

    # -------------------------------------------------------------------------
    # Structured logging methods (new API)
    # -------------------------------------------------------------------------

    def invocation(
        self,
        hook_event: str,
        tool_name: str,
        **context: Any,
    ) -> None:
        """
        Log a hook invocation.

        Args:
            hook_event: The hook event type (PreToolUse, PostToolUse).
            tool_name: Name of the tool being invoked.
            **context: Additional context (file_path, command, etc.).
        """
        ctx = dict(context)
        ctx["hook_event"] = hook_event
        ctx["tool_name"] = tool_name
        self._write_structured("info", "invocation", ctx)

    def response(
        self,
        hook_event: str,
        outcome: str,
        tool_name: str,
        raw_response: dict[str, Any] | None = None,
        reason: str | None = None,
        response_time_ms: float | None = None,
        **context: Any,
    ) -> None:
        """
        Log a hook response.

        Args:
            hook_event: The hook event type (PreToolUse, PostToolUse).
            outcome: The outcome (allow, deny, ask, skip, context_added, acknowledged).
            tool_name: Name of the tool.
            raw_response: The raw JSON response from the hook (for debugging).
            reason: Optional reason for the outcome.
            response_time_ms: Optional response time in milliseconds.
            **context: Additional context as key-value pairs.
        """
        ctx = dict(context)
        ctx["hook_event"] = hook_event
        ctx["tool_name"] = tool_name
        ctx["outcome"] = outcome

        if reason:
            ctx["reason"] = reason

        if raw_response is not None:
            ctx["raw_response"] = raw_response

        if response_time_ms is not None:
            ctx["response_time_ms"] = round(response_time_ms, 2)

        self._write_structured("info", "response", ctx)

    # -------------------------------------------------------------------------
    # General logging methods
    # -------------------------------------------------------------------------

    def debug(self, message: str, **context: Any) -> None:
        """
        Log a debug message.

        Args:
            message: The debug message.
            **context: Additional context as key-value pairs.
        """
        ctx = dict(context)
        ctx["msg"] = message
        self._write_structured("debug", "debug", ctx)

    def info(self, message: str, **context: Any) -> None:
        """
        Log an info message.

        Args:
            message: The message to log.
            **context: Additional context as key-value pairs.
        """
        ctx = dict(context)
        ctx["msg"] = message
        self._write_structured("info", "debug", ctx)

    def warning(self, message: str, **context: Any) -> None:
        """
        Log a warning message.

        Args:
            message: The warning message.
            **context: Additional context as key-value pairs.
        """
        ctx = dict(context)
        ctx["msg"] = message
        self._write_structured("warning", "debug", ctx)

    def error(self, message: str, **context: Any) -> None:
        """
        Log an error message.

        Args:
            message: The error message.
            **context: Additional context as key-value pairs.
        """
        ctx = dict(context)
        ctx["msg"] = message
        self._write_structured("error", "debug", ctx)

    # -------------------------------------------------------------------------
    # Deprecated methods (for backward compatibility)
    # -------------------------------------------------------------------------

    def decision(
        self,
        decision: str,
        reason: str | None = None,
        response_time_ms: float | None = None,
        **context: Any,
    ) -> None:
        """
        Log a hook decision.

        DEPRECATED: Use response() instead for new code.

        Args:
            decision: The decision made ("allow", "deny", "ask", "skip", "context").
            reason: Optional reason for the decision.
            response_time_ms: Optional response time in milliseconds.
            **context: Additional context as key-value pairs.
        """
        # Map to new response() method
        tool_name = context.pop("tool_name", "unknown")
        hook_event = context.pop("hook_event", "unknown")
        self.response(
            hook_event=hook_event,
            outcome=decision,
            tool_name=tool_name,
            reason=reason,
            response_time_ms=response_time_ms,
            **context,
        )

    # -------------------------------------------------------------------------
    # Internal methods
    # -------------------------------------------------------------------------

    def _write_structured(
        self,
        level: str,
        entry_type: str,
        context: dict[str, Any],
    ) -> None:
        """Write a structured JSONL log entry."""
        if not self._log_file:
            return

        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": level,
            "type": entry_type,
            "hook": self._hook_name,
        }

        if self._namespace:
            entry["namespace"] = self._namespace

        if self._session_id:
            entry["session"] = self._session_id

        # Add context fields directly to the entry
        entry.update(context)

        try:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            with self._log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            # Fail silently - logging should never break the hook
            pass


class _NullLogger(HookLogger):
    """A logger that discards all output."""

    def __init__(self) -> None:
        super().__init__(hook_name="null", session_id=None, log_file=None)

    def _write_structured(
        self,
        level: str,
        entry_type: str,
        context: dict[str, Any],
    ) -> None:
        """Discard the log entry."""
        pass
