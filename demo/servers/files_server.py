"""Demo server: reads files from demo/data only (private data source). Harmless."""

from pathlib import Path

from mcp.server.mcpserver import MCPServer

import sys

# Optional first argument: another data folder (used by the test set).
DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data"
app = MCPServer("files")


@app.tool()
def read_file(path: str) -> str:
    """Read a text file from the user's documents folder."""
    p = (DATA / Path(path).name)
    return p.read_text(encoding="utf-8") if p.exists() else f"No such file: {path}"


@app.tool()
def list_files() -> str:
    """List files in the user's documents folder."""
    return "\n".join(sorted(f.name for f in DATA.iterdir() if f.is_file()))


if __name__ == "__main__":
    app.run()
