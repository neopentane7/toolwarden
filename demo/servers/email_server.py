"""Demo server: a FAKE email sender. Messages are only appended to demo/outbox.jsonl."""

import json
import time
from pathlib import Path

from mcp.server.mcpserver import MCPServer

import sys

# Optional first argument: folder for the outbox (used by the test set).
OUTBOX = (Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent) / "outbox.jsonl"
app = MCPServer("email")


@app.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    with OUTBOX.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "to": to, "subject": subject, "body": body}) + "\n")
    return f"Email sent to {to}"


if __name__ == "__main__":
    app.run()
