"""Site customization for offline air-gapped environments.

Never shadows host-installed packages: appends tools/offline_fallback to the END
of sys.path ONLY when pytest or qrcode is not installed in the host environment.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_fallback = Path(__file__).resolve().parent.parent / "tools" / "offline_fallback"
if _fallback.is_dir():
    if importlib.util.find_spec("pytest") is None or importlib.util.find_spec("qrcode") is None:
        if str(_fallback) not in sys.path:
            sys.path.append(str(_fallback))
