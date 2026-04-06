"""Loguru logging configuration for PSI.

Two output modes:
- TTY: colorized, human-readable
- Non-TTY or --log-json: structured JSON for log aggregators

All output goes to stderr so systemd captures it in the journal.
"""

from __future__ import annotations

import sys

from loguru import logger

_TTY_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level: <8}</level> <level>{message}</level>"
)


def configure_logging(level: str = "INFO", json_output: bool | None = None) -> None:
    """Configure loguru handlers.

    Args:
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR).
        json_output: Force JSON output. If None, auto-detect from TTY.
    """
    logger.remove()

    use_json = json_output if json_output is not None else not sys.stderr.isatty()

    if use_json:
        logger.add(sys.stderr, serialize=True, level=level)
    else:
        logger.add(sys.stderr, format=_TTY_FORMAT, level=level, colorize=True)
