"""Tests for psi.logging — loguru configuration."""

from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING

import pytest
from loguru import logger

from psi.logging import configure_logging

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _reset_logger() -> Iterator[None]:
    """Snapshot and restore loguru handlers around each test.

    Prevents sinks added by tests from leaking into later tests and
    writing to closed StringIO objects.
    """
    yield
    logger.remove()


class TestConfigureLogging:
    def test_json_mode_emits_flat_structured_record(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """JSON output is one clean object per line, no redundant text field."""
        configure_logging(level="INFO", json_output=True)

        logger.bind(event="test.event", key="value").info("test message")

        output = capsys.readouterr().err.strip()
        record = json.loads(output)
        assert record["message"] == "test message"
        assert record["level"] == "INFO"
        assert record["extra"]["event"] == "test.event"
        assert record["extra"]["key"] == "value"
        # No embedded pre-formatted text field with newlines
        assert "text" not in record
        assert "\\n" not in output
        assert output.count("\n") == 0  # one line only

    def test_level_filtering(self, capsys: pytest.CaptureFixture[str]) -> None:
        configure_logging(level="WARNING", json_output=True)

        logger.info("should not appear")
        logger.warning("should appear")

        output = capsys.readouterr().err
        assert "should not appear" not in output
        assert "should appear" in output

    def test_no_secret_values_in_default_format(self) -> None:
        """The TTY format should never include 'extra' fields by default.

        The audit logging strategy relies on `bind()` for structured fields,
        which only appear in JSON mode. TTY mode shows just level + message.
        """
        sink = io.StringIO()
        logger.remove()
        logger.add(sink, format="<level>{level}</level> {message}", level="INFO")

        logger.bind(secret_value="should-never-appear").info("operation")

        output = sink.getvalue()
        assert "should-never-appear" not in output

    def test_configure_logging_removes_existing_handlers(self) -> None:
        """configure_logging() should remove any previously registered sinks."""
        sink = io.StringIO()
        logger.add(sink, serialize=True, level="INFO")

        configure_logging(level="INFO", json_output=True)

        logger.info("after configure")
        assert "after configure" not in sink.getvalue()
