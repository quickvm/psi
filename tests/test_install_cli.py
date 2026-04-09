"""Tests for the `psi install` CLI command."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from psi.cli import app

runner = CliRunner()


class TestInstallStdout:
    def test_stdout_prints_conf_and_skips_install(self) -> None:
        """`psi install --stdout` prints the conf and never calls install_driver_conf."""
        rendered = '[secrets]\ndriver = "shell"\n'
        with (
            patch("psi.cli.load_settings") as mock_load,
            patch("psi.installer.render_driver_conf", return_value=rendered) as mock_render,
            patch("psi.installer.install_driver_conf") as mock_install,
        ):
            result = runner.invoke(app, ["install", "--stdout"])

        assert result.exit_code == 0
        assert rendered in result.stdout
        assert "Wrote" not in result.stdout
        mock_render.assert_called_once_with(mock_load.return_value)
        mock_install.assert_not_called()

    def test_default_writes_conf_and_skips_render(self) -> None:
        """`psi install` (no flag) calls install_driver_conf, not render_driver_conf."""
        with (
            patch("psi.cli.load_settings") as mock_load,
            patch("psi.installer.render_driver_conf") as mock_render,
            patch("psi.installer.install_driver_conf") as mock_install,
        ):
            result = runner.invoke(app, ["install"])

        assert result.exit_code == 0
        mock_install.assert_called_once_with(mock_load.return_value)
        mock_render.assert_not_called()
