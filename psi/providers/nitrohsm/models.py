"""NitroHSM provider models and configuration."""

from __future__ import annotations

from pathlib import Path  # noqa: TCH003 — Pydantic needs Path at runtime

from pydantic import BaseModel


class NitroHSMConfig(BaseModel):
    """Configuration for the NitroHSM provider."""

    pkcs11_module: str = "/usr/lib64/pkcs11/opensc-pkcs11.so"
    slot: int = 0
    key_label: str = "podman-secrets"
    key_id: str = "02"
    pin: str | None = None
    public_key_cache: Path | None = None
    pcscd_volume: str = "pcscd-socket"
