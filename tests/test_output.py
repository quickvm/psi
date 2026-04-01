"""Tests for psi.output — TTY-aware rendering."""

from __future__ import annotations

import json
from unittest.mock import patch

from rich.table import Table

from psi.models import SecretStatus
from psi.output import render_or_json


class TestRenderOrJson:
    def test_force_json(self, capsys) -> None:
        data = [
            SecretStatus(name="KEY", provider="infisical", detail="proj:/app", registered=True),
        ]
        table = Table()
        render_or_json(table, data, force_json=True)
        output = capsys.readouterr().out
        parsed = json.loads(output)
        assert len(parsed) == 1
        assert parsed[0]["name"] == "KEY"
        assert parsed[0]["registered"] is True

    def test_json_on_non_tty(self, capsys) -> None:
        data = [
            SecretStatus(name="A", provider="infisical", detail="", registered=True),
        ]
        table = Table()
        with patch("psi.output.sys.stdout.isatty", return_value=False):
            render_or_json(table, data, force_json=False)
        output = capsys.readouterr().out
        parsed = json.loads(output)
        assert parsed[0]["name"] == "A"

    def test_rich_table_on_tty(self) -> None:
        data = [
            SecretStatus(name="A", provider="infisical", detail="", registered=True),
        ]
        table = Table()
        table.add_column("Name")
        table.add_row("A")
        with patch("psi.output.sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            with patch("psi.output.Console") as mock_console_cls:
                render_or_json(table, data, force_json=False)
                mock_console_cls.return_value.print.assert_called_once_with(table)

    def test_empty_data(self, capsys) -> None:
        table = Table()
        render_or_json(table, [], force_json=True)
        output = capsys.readouterr().out
        assert json.loads(output) == []
