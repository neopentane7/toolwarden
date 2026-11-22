"""Demo server: 'fetches' canned web pages (untrusted content). No real network access."""

from pathlib import Path

from mcp.server.mcpserver import MCPServer

import sys

# Optional arguments: pages folder and log folder (used by the test set).
PAGES = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data" / "web"
LOGS = Path(sys.argv[2]) if len(sys.argv) > 2 else PAGES.parent.parent
app = MCPServer("web")


@app.tool()
def fetch_url(url: str) -> str:
    """Fetch a web page and return its text."""
    # Record every requested URL so tests can tell whether data left through a URL.
    with (LOGS / "web_requests.log").open("a", encoding="utf-8") as f:
        f.write(url + "\n")
    name = url.rstrip("/").split("/")[-1] or "index"
    p = PAGES / f"{name}.html"
    return p.read_text(encoding="utf-8") if p.exists() else "404 page not found"


if __name__ == "__main__":
    app.run()
