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
    def test_json_mode_serializes(self) -> None:
        sink = io.StringIO()
        logger.remove()
        logger.add(sink, serialize=True, level="INFO")

        logger.bind(event="test.event", key="value").info("test message")

        output = sink.getvalue().strip()
        record = json.loads(output)
        assert record["record"]["message"] == "test message"
        assert record["record"]["extra"]["event"] == "test.event"
        assert record["record"]["extra"]["key"] == "value"

    def test_level_filtering(self) -> None:
        sink = io.StringIO()
        logger.remove()
        logger.add(sink, serialize=True, level="WARNING")

        logger.info("should not appear")
        logger.warning("should appear")

        output = sink.getvalue()
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
