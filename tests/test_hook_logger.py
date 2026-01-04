"""Tests for HookLogger."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_hook_utils.logging import HookLogger


class TestHookLoggerCreateDefault:
    """Tests for HookLogger.create_default()."""

    def test_creates_logger_with_default_path(self, tmp_path: Path) -> None:
        """Should create logger with .claude/logs/hooks.jsonl path."""
        logger = HookLogger.create_default("TestHook", cwd=str(tmp_path))

        assert logger._hook_name == "TestHook"
        assert logger._log_file == tmp_path / ".claude/logs/hooks.jsonl"

    def test_creates_logger_with_namespace_subdirectory(self, tmp_path: Path) -> None:
        """Should create logger with namespace subdirectory."""
        logger = HookLogger.create_default(
            "TestHook",
            namespace="my-plugin",
            cwd=str(tmp_path),
        )

        assert logger._hook_name == "TestHook"
        assert logger._namespace == "my-plugin"
        assert logger._log_file == tmp_path / ".claude/logs/my-plugin/hooks.jsonl"

    def test_creates_logger_with_session_id(self, tmp_path: Path) -> None:
        """Should create logger with session_id."""
        logger = HookLogger.create_default(
            "TestHook",
            session_id="session123",
            cwd=str(tmp_path),
        )

        assert logger._session_id == "session123"

    def test_env_var_overrides_log_dir(self, tmp_path: Path) -> None:
        """CLAUDE_HOOK_LOG_DIR should override default directory."""
        custom_dir = tmp_path / "custom-logs"

        with patch.dict(os.environ, {"CLAUDE_HOOK_LOG_DIR": str(custom_dir)}):
            logger = HookLogger.create_default("TestHook", cwd=str(tmp_path))

        assert logger._log_file == custom_dir / "hooks.jsonl"

    def test_env_var_overrides_namespace(self, tmp_path: Path) -> None:
        """CLAUDE_HOOK_LOG_NAMESPACE should override namespace parameter."""
        with patch.dict(os.environ, {"CLAUDE_HOOK_LOG_NAMESPACE": "env-namespace"}):
            logger = HookLogger.create_default(
                "TestHook",
                namespace="param-namespace",
                cwd=str(tmp_path),
            )

        assert logger._namespace == "env-namespace"
        assert logger._log_file == tmp_path / ".claude/logs/env-namespace/hooks.jsonl"


class TestHookLoggerWithSession:
    """Tests for HookLogger.with_session()."""

    def test_returns_new_logger_with_session(self, tmp_path: Path) -> None:
        """Should return new logger with session_id set."""
        logger = HookLogger.create_default("TestHook", cwd=str(tmp_path))
        new_logger = logger.with_session("session456")

        assert new_logger._session_id == "session456"
        assert logger._session_id is None  # Original unchanged

    def test_preserves_hook_name(self, tmp_path: Path) -> None:
        """Should preserve hook_name."""
        logger = HookLogger.create_default("TestHook", cwd=str(tmp_path))
        new_logger = logger.with_session("session456")

        assert new_logger._hook_name == "TestHook"

    def test_preserves_namespace(self, tmp_path: Path) -> None:
        """Should preserve namespace."""
        logger = HookLogger.create_default(
            "TestHook",
            namespace="my-plugin",
            cwd=str(tmp_path),
        )
        new_logger = logger.with_session("session456")

        assert new_logger._namespace == "my-plugin"

    def test_preserves_log_file(self, tmp_path: Path) -> None:
        """Should preserve log_file path."""
        logger = HookLogger.create_default("TestHook", cwd=str(tmp_path))
        new_logger = logger.with_session("session456")

        assert new_logger._log_file == logger._log_file


class TestHookLoggerOutput:
    """Tests for HookLogger output format."""

    def test_writes_jsonl_format(self, tmp_path: Path) -> None:
        """Should write valid JSONL (one JSON object per line)."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Test message")
        logger.info("Second message")

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2

        # Each line should be valid JSON
        for line in lines:
            entry = json.loads(line)
            assert isinstance(entry, dict)

    def test_includes_required_fields(self, tmp_path: Path) -> None:
        """Should include ts, level, hook, and msg fields."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Test message")

        entry = json.loads(log_file.read_text().strip())
        assert "ts" in entry
        assert entry["level"] == "INFO"
        assert entry["hook"] == "TestHook"
        assert entry["msg"] == "Test message"

    def test_includes_namespace_when_set(self, tmp_path: Path) -> None:
        """Should include namespace field when set."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file, namespace="my-plugin")

        logger.info("Test message")

        entry = json.loads(log_file.read_text().strip())
        assert entry["namespace"] == "my-plugin"

    def test_excludes_namespace_when_not_set(self, tmp_path: Path) -> None:
        """Should not include namespace field when not set."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Test message")

        entry = json.loads(log_file.read_text().strip())
        assert "namespace" not in entry

    def test_includes_session_when_set(self, tmp_path: Path) -> None:
        """Should include session field when set."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", session_id="session123", log_file=log_file)

        logger.info("Test message")

        entry = json.loads(log_file.read_text().strip())
        assert entry["session"] == "session123"

    def test_excludes_session_when_not_set(self, tmp_path: Path) -> None:
        """Should not include session field when not set."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Test message")

        entry = json.loads(log_file.read_text().strip())
        assert "session" not in entry

    def test_includes_context_fields(self, tmp_path: Path) -> None:
        """Should include context fields in entry."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Test message", file_path="/path/to/file", count=42)

        entry = json.loads(log_file.read_text().strip())
        assert entry["file_path"] == "/path/to/file"
        assert entry["count"] == 42

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """Should create parent directories if they don't exist."""
        log_file = tmp_path / "deep/nested/path/test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Test message")

        assert log_file.exists()


class TestHookLoggerLevels:
    """Tests for different log levels."""

    def test_info_level(self, tmp_path: Path) -> None:
        """info() should log with INFO level."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.info("Info message")

        entry = json.loads(log_file.read_text().strip())
        assert entry["level"] == "INFO"

    def test_error_level(self, tmp_path: Path) -> None:
        """error() should log with ERROR level."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.error("Error message")

        entry = json.loads(log_file.read_text().strip())
        assert entry["level"] == "ERROR"

    def test_debug_level(self, tmp_path: Path) -> None:
        """debug() should log with DEBUG level."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.debug("Debug message")

        entry = json.loads(log_file.read_text().strip())
        assert entry["level"] == "DEBUG"

    def test_decision_level(self, tmp_path: Path) -> None:
        """decision() should log with DECISION level."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.decision("allow", reason="Test reason")

        entry = json.loads(log_file.read_text().strip())
        assert entry["level"] == "DECISION"
        assert entry["decision"] == "allow"
        assert entry["reason"] == "Test reason"

    def test_decision_with_response_time(self, tmp_path: Path) -> None:
        """decision() should include response_time_ms when provided."""
        log_file = tmp_path / "test.jsonl"
        logger = HookLogger("TestHook", log_file=log_file)

        logger.decision("deny", response_time_ms=15.5)

        entry = json.loads(log_file.read_text().strip())
        assert entry["response_time_ms"] == 15.5


class TestHookLoggerNull:
    """Tests for HookLogger.null()."""

    def test_null_logger_does_not_write(self, tmp_path: Path) -> None:
        """null() logger should not write anything."""
        logger = HookLogger.null()

        # Should not raise even though there's no log file
        logger.info("Test message")
        logger.error("Error message")
        logger.decision("allow")

        # Verify no files were created
        assert not list(tmp_path.glob("**/*.jsonl"))

    def test_null_logger_has_null_hook_name(self) -> None:
        """null() logger should have 'null' as hook_name."""
        logger = HookLogger.null()
        assert logger._hook_name == "null"


class TestHookLoggerTiming:
    """Tests for timing methods."""

    def test_elapsed_ms_returns_milliseconds(self, tmp_path: Path) -> None:
        """elapsed_ms() should return time in milliseconds."""
        logger = HookLogger("TestHook", log_file=tmp_path / "test.jsonl")

        start = logger.start_timer()
        elapsed = logger.elapsed_ms(start)

        assert elapsed >= 0
        assert isinstance(elapsed, float)

    def test_elapsed_uses_last_start_timer(self, tmp_path: Path) -> None:
        """elapsed() should use last start_timer() call if no start provided."""
        logger = HookLogger("TestHook", log_file=tmp_path / "test.jsonl")

        logger.start_timer()
        elapsed = logger.elapsed()

        assert elapsed >= 0


class TestHookLoggerDisabled:
    """Tests for disabled logging (no log_file)."""

    def test_no_log_file_does_not_write(self) -> None:
        """Logger without log_file should not write anything."""
        logger = HookLogger("TestHook", log_file=None)

        # Should not raise
        logger.info("Test message")
        logger.error("Error message")
        logger.decision("allow")
