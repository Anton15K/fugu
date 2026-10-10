"""Provider authentication stays in the parent process, separate from targets."""
from __future__ import annotations

import os
from typing import Mapping


def credential_free_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Copy normal child settings without either provider credential."""
    return {key: value for key, value in (os.environ if environ is None else environ).items()
            if key not in {'NEBIUS_API_KEY', 'TAVILY_API_KEY'}}
