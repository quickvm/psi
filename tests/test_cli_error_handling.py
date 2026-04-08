"""Tests for top-level CLI error handling in psi.cli.main()."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from psi.errors import ConfigError, ProviderError, PsiError


class TestMainErrorHandler:
    def test_psi_error_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("psi.cli.app", side_effect=PsiError("bad config")):
            from psi.cli import main

            with pytest.raises(SystemExit, match="1"):
                main()

        captured = capsys.readouterr()
        assert "bad config" in captured.out

    def test_config_error_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("psi.cli.app", side_effect=ConfigError("missing field")):
            from psi.cli import main

            with pytest.raises(SystemExit, match="1"):
                main()

        captured = capsys.readouterr()
        assert "missing field" in captured.out

    def test_provider_error_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch(
            "psi.cli.app",
            side_effect=ProviderError("HSM down", provider_name="nitrokeyhsm"),
        ):
            from psi.cli import main

            with pytest.raises(SystemExit, match="1"):
                main()

        captured = capsys.readouterr()
        assert "HSM down" in captured.out

    def test_unexpected_exception_exits_2(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("psi.cli.app", side_effect=RuntimeError("unexpected")):
            from psi.cli import main

            with pytest.raises(SystemExit, match="2"):
                main()

        captured = capsys.readouterr()
        assert "this is a bug" in captured.out

    def test_keyboard_interrupt_exits_130(self) -> None:
        with patch("psi.cli.app", side_effect=KeyboardInterrupt):
            from psi.cli import main

            with pytest.raises(SystemExit, match="130"):
                main()

    def test_httpx_connect_error_exits_1_clean(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Stray httpx errors surface as a clean 'Network error', not a bug panic."""
        with patch("psi.cli.app", side_effect=httpx.ConnectError("refused")):
            from psi.cli import main

            with pytest.raises(SystemExit, match="1"):
                main()

        captured = capsys.readouterr()
        assert "Network error" in captured.out
        assert "refused" in captured.out
        assert "this is a bug" not in captured.out

    def test_httpx_status_error_exits_1_clean(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A raw HTTPStatusError (missed by provider wrapping) is still clean."""
        request = httpx.Request("POST", "http://test")
        response = httpx.Response(502, request=request)
        exc = httpx.HTTPStatusError("502", request=request, response=response)

        with patch("psi.cli.app", side_effect=exc):
            from psi.cli import main

            with pytest.raises(SystemExit, match="1"):
                main()

        captured = capsys.readouterr()
        assert "Network error" in captured.out
        assert "this is a bug" not in captured.out
