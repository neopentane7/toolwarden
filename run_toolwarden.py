"""Entry point for agent apps (Claude Desktop, Cursor): works from any working folder.

Example app config:  command = full path to python, args = [full path to this file,
"run", "--policy", full path to policy.yaml]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from toolwarden.__main__ import main  # noqa: E402

main()
