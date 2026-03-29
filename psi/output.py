"""TTY-aware output: Rich tables for terminals, JSON for pipes."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from rich.console import Console

if TYPE_CHECKING:
    from rich.table import Table


def render_or_json(
    table: Table,
    data: list[Any],
    force_json: bool = False,
) -> None:
    """Print a Rich table if on a TTY, or JSON if piped/forced.

    Args:
        table: Pre-built Rich Table for terminal display.
        data: Pydantic models to serialize as JSON.
        force_json: If True, output JSON regardless of TTY.
    """
    if force_json or not sys.stdout.isatty():
        print(json.dumps([item.model_dump() for item in data], indent=2))
    else:
        Console().print(table)
