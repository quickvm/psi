"""Loguru logging configuration for PSI.

Two output modes:
- TTY: colorized, human-readable
- Non-TTY or --log-json: structured JSON for log aggregators

All output goes to stderr so systemd captures it in the journal.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Message

_TTY_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> <level>{level: <8}</level> <level>{message}</level>"
)


def _json_sink(message: Message) -> None:
    """Emit one structured JSON object per log record, no redundant text field.

    Loguru's ``serialize=True`` wraps output as ``{"text": "...\\n", "record":
    {...}}`` where ``text`` is a pre-formatted duplicate of the structured data
    with an embedded newline. Log aggregators then show literal ``\\n`` in the
    JSON. Emit just the record fields so the output is flat and clean.
    """
    record = message.record
    payload: dict[str, object] = {
        "time": record["time"].isoformat(),
        "level": record["level"].name,
        "message": record["message"],
        "module": record["module"],
        "function": record["function"],
        "line": record["line"],
        "name": record["name"],
    }
    if record["extra"]:
        payload["extra"] = dict(record["extra"])
    if record["exception"] is not None:
        payload["exception"] = str(record["exception"])
    sys.stderr.write(json.dumps(payload, default=str) + "\n")


def configure_logging(level: str = "INFO", json_output: bool | None = None) -> None:
    """Configure loguru handlers.

    Args:
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR).
        json_output: Force JSON output. If None, auto-detect from TTY.
    """
    logger.remove()

    use_json = json_output if json_output is not None else not sys.stderr.isatty()

    if use_json:
        logger.add(_json_sink, level=level)
    else:
        logger.add(sys.stderr, format=_TTY_FORMAT, level=level, colorize=True)
