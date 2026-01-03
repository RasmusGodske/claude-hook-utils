"""Simple hook logger for file-based logging."""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any


class HookLogger:
    """
    Simple file-based logger for hook handlers.

    Provides methods for logging events, decisions, and timing information.

    Example:
        logger = HookLogger(log_file="my-validator.log")
        logger.info("Processing file", file_path="/path/to/file.php")

        start = logger.start_timer()
        # ... do work ...
        logger.decision("allow", response_time=logger.elapsed(start))
    """

    def __init__(
        self,
        log_file: str | Path | None = None,
        include_timestamp: bool = True,
    ) -> None:
        """
        Initialize the logger.

        Args:
            log_file: Path to log file. If None, logs to stderr.
            include_timestamp: Whether to include timestamps in log entries.
        """
        self._log_file = Path(log_file) if log_file else None
        self._include_timestamp = include_timestamp
        self._start_time: float | None = None

    @staticmethod
    def null() -> HookLogger:
        """
        Create a no-op logger that discards all output.

        Useful as a default when no logging is desired.
        """
        return _NullLogger()

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
    # Logging methods
    # -------------------------------------------------------------------------

    def info(self, message: str, **context: Any) -> None:
        """
        Log an info message.

        Args:
            message: The message to log.
            **context: Additional context as key-value pairs.
        """
        self._write("INFO", message, context)

    def error(self, message: str, **context: Any) -> None:
        """
        Log an error message.

        Args:
            message: The error message.
            **context: Additional context as key-value pairs.
        """
        self._write("ERROR", message, context)

    def debug(self, message: str, **context: Any) -> None:
        """
        Log a debug message.

        Args:
            message: The debug message.
            **context: Additional context as key-value pairs.
        """
        self._write("DEBUG", message, context)

    def decision(
        self,
        decision: str,
        reason: str | None = None,
        response_time_ms: float | None = None,
        **context: Any,
    ) -> None:
        """
        Log a hook decision.

        Args:
            decision: The decision made ("allow", "deny", "ask", "skip").
            reason: Optional reason for the decision.
            response_time_ms: Optional response time in milliseconds.
            **context: Additional context as key-value pairs.
        """
        ctx = dict(context)
        ctx["decision"] = decision

        if reason:
            ctx["reason"] = reason

        if response_time_ms is not None:
            ctx["response_time_ms"] = f"{response_time_ms:.2f}"

        self._write("DECISION", f"decision={decision}", ctx)

    # -------------------------------------------------------------------------
    # Internal methods
    # -------------------------------------------------------------------------

    def _write(self, level: str, message: str, context: dict[str, Any]) -> None:
        """Write a log entry."""
        parts = []

        if self._include_timestamp:
            timestamp = datetime.now().isoformat(timespec="milliseconds")
            parts.append(f"[{timestamp}]")

        parts.append(f"[{level}]")
        parts.append(message)

        if context:
            context_str = " ".join(f"{k}={v}" for k, v in context.items())
            parts.append(f"| {context_str}")

        line = " ".join(parts)

        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            with self._log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        else:
            import sys

            print(line, file=sys.stderr)


class _NullLogger(HookLogger):
    """A logger that discards all output."""

    def __init__(self) -> None:
        super().__init__(log_file=None, include_timestamp=False)

    def _write(self, level: str, message: str, context: dict[str, Any]) -> None:
        """Discard the log entry."""
        pass
