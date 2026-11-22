"""Real file server: reads files from a real folder on your computer (read-only).

The folder is the first command-line argument (default: ~/toolwarden_sandbox). Paths outside
it are refused. Put only test files there - never real passwords.
"""

import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path.home() / "toolwarden_sandbox").resolve()
ROOT.mkdir(parents=True, exist_ok=True)
app = MCPServer("files")


def _safe(path: str) -> Path | None:
    p = (ROOT / path).resolve()
    return p if p == ROOT or ROOT in p.parents else None


@app.tool()
def read_file(path: str) -> str:
    """Read a text file from the user's documents folder."""
    p = _safe(path) or _safe(Path(path).name)
    if p is None or not p.is_file():
        return f"No such file: {path}"
    return p.read_text(encoding="utf-8", errors="replace")[:20000]


@app.tool()
def list_files() -> str:
    """List files in the user's documents folder."""
    return "\n".join(sorted(str(f.relative_to(ROOT)) for f in ROOT.rglob("*") if f.is_file())[:200])


if __name__ == "__main__":
    app.run()
