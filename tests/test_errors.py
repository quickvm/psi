"""Tests for psi.errors — exception hierarchy."""

from __future__ import annotations

from psi.errors import ConfigError, ProviderError, PsiError, SecretNotFoundError


class TestExceptionHierarchy:
    def test_psi_error_is_exception(self) -> None:
        assert issubclass(PsiError, Exception)

    def test_config_error_is_psi_error(self) -> None:
        assert issubclass(ConfigError, PsiError)

    def test_provider_error_is_psi_error(self) -> None:
        assert issubclass(ProviderError, PsiError)

    def test_secret_not_found_is_psi_error(self) -> None:
        assert issubclass(SecretNotFoundError, PsiError)


class TestPsiError:
    def test_str_returns_message(self) -> None:
        err = PsiError("something went wrong")
        assert str(err) == "something went wrong"


class TestProviderError:
    def test_provider_name_attribute(self) -> None:
        err = ProviderError("bad", provider_name="infisical")
        assert err.provider_name == "infisical"

    def test_provider_name_defaults_empty(self) -> None:
        err = ProviderError("bad")
        assert err.provider_name == ""

    def test_str_returns_message(self) -> None:
        err = ProviderError("HSM failed", provider_name="nitrokeyhsm")
        assert str(err) == "HSM failed"


class TestConfigError:
    def test_str_returns_message(self) -> None:
        err = ConfigError("missing field")
        assert str(err) == "missing field"


class TestSecretNotFoundError:
    def test_str_returns_message(self) -> None:
        err = SecretNotFoundError("no mapping for secret: foo")
        assert str(err) == "no mapping for secret: foo"
