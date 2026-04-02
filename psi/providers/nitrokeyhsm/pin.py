"""PIN resolution for Nitrokey HSM provider.

Resolution order:
1. $CREDENTIALS_DIRECTORY/hsm-pin (systemd-creds / TPM)
2. Config 'pin' field
3. PSI_NITROKEYHSM_PIN env var
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from psi.providers.nitrokeyhsm.models import NitrokeyHSMConfig


def resolve_pin(config: NitrokeyHSMConfig) -> str:
    """Resolve the HSM PIN from credentials, config, or environment.

    Returns:
        The PIN string.

    Raises:
        RuntimeError: If no PIN source is available.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        pin_path = Path(creds_dir) / "hsm-pin"
        if pin_path.exists():
            return pin_path.read_text().strip()

    if config.pin:
        return config.pin

    env_pin = os.environ.get("PSI_NITROKEYHSM_PIN")
    if env_pin:
        return env_pin

    from psi.errors import ProviderError

    msg = (
        "No HSM PIN found. Provide it via one of:\n"
        "  1. systemd LoadCredentialEncrypted=hsm-pin "
        "(sets $CREDENTIALS_DIRECTORY)\n"
        "  2. 'pin' field in providers.nitrokeyhsm config\n"
        "  3. PSI_NITROKEYHSM_PIN environment variable"
    )
    raise ProviderError(msg, provider_name="nitrokeyhsm")
