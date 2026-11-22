"""Real web fetch server: downloads real pages from the internet and returns their text.

Like common fetch tools, it strips HTML tags and scripts but keeps all visible text, so a page
that contains hidden-in-plain-sight instructions reaches the model as text.
"""

import html
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

from mcp.server.mcpserver import MCPServer

app = MCPServer("web")
MAX_BYTES = 300_000


def _private_address(url: str) -> bool:
    """True for this computer and the local network (fix 19 Nov audit): an injected page must not
    be able to make the agent read the dashboard, a router page or other local services."""
    try:
        host = urlparse(url).hostname or ""
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except (OSError, ValueError):
        return False  # the fetch below reports the error
    return any(ipaddress.ip_address(a.split("%")[0]).is_private or ipaddress.ip_address(a.split("%")[0]).is_loopback
               or ipaddress.ip_address(a.split("%")[0]).is_link_local for a in addrs)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _private_address(newurl):
            raise urllib.error.URLError("redirect to a local address refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_NoRedirect)


@app.tool()
def fetch_url(url: str) -> str:
    """Fetch a web page and return its text."""
    if not url.startswith(("http://", "https://")):
        return "Only http and https URLs are supported."
    if _private_address(url):
        return "Refused: this tool only fetches public internet pages, not this computer or the local network."
    req = urllib.request.Request(url, headers={"User-Agent": "ToolWarden-demo/0.4"})
    try:
        with _opener.open(req, timeout=20) as r:
            raw = r.read(MAX_BYTES).decode(r.headers.get_content_charset() or "utf-8", errors="replace")
            ctype = r.headers.get("Content-Type", "")
    except Exception as e:  # noqa: BLE001 - report network errors to the model as text
        return f"Could not fetch {url}: {e}"
    if "html" not in ctype:
        return raw[:20000]
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(re.sub(r"[ \t]+", " ", text))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return text[:20000]


if __name__ == "__main__":
    app.run()
