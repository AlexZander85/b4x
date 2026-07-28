#!/usr/bin/env python3
"""Controlled Keenetic/Android field validation for B4 classifier v2.3."""

from pathlib import Path
import sys

_MODULE_DIR = str(Path(__file__).resolve().parent)
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

from field_common import *  # noqa: F401,F403,E402
from field_evaluation import *  # noqa: F401,F403,E402
from field_cli import *  # noqa: F401,F403,E402


if __name__ == "__main__":
    raise SystemExit(main())
