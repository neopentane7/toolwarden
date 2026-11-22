"""Local admin dashboard: approvals, live activity, tools and the proposed policy.

Runs on 127.0.0.1 only. A random token in the URL protects the approve/deny endpoints from
other web pages in your browser (a page on the internet cannot read the token).

    python run_toolwarden.py ui            (opens the browser)
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .report import load_events, plain_english, propose_policy
from .state import ApprovalStore, PinStore

HTML = Path(__file__).with_name("ui_index.html")


def build_state(sd: Path) -> dict:
    events = load_events(sd / "events.jsonl")
    calls = [e for e in events if e.get("event") == "call"]
    seen: dict[str, dict] = {}
    for e in events:
        if e.get("event") == "tool_seen":
            seen[e["tool"]] = e
    pins = PinStore(sd / "pins.json").pins
    tools = []
    for key, pin in sorted(pins.items()):
        info = seen.get(key, {})
        tools.append({"tool": key, "status": pin.get("status"), "labels": info.get("labels", []),
                      "reasons": info.get("reasons", [])})
    store = ApprovalStore(sd / "approvals.json", 60)
    approvals = store._load()
    # What the held call wanted to send (already redacted in the log), so the admin does not
    # approve blind (fix 19 Nov audit).
    args_by_req = {e["request_id"]: e.get("args", {}) for e in calls if e.get("request_id")}
    appr = sorted(({"id": k, **v, "status": store.status(k) or v["status"],
                    "args": json.dumps(args_by_req.get(k, {}), ensure_ascii=False)[:600]}
                   for k, v in approvals.items()),
                  key=lambda r: r.get("created_at", 0), reverse=True)[:50]
    mode = next((e.get("mode") for e in reversed(calls) if e.get("mode")), None)
    # Real stops and shadow-mode flags are counted apart (fix 22 Nov review: after switching from
    # shadow to enforce with the same state folder, calls that only would have been stopped were
    # shown as stopped, and not as allowed although they went through).
    stopped = [e for e in calls if e["decision"] in ("block", "approval_requested")]
    would = [e for e in calls if e["decision"] == "would_block"]
    ai =[e for e in events if e.get("event") == "ai_review"]
    ok_ms = sorted(e["ms"] for e in ai if not e.get("error"))
    ai_info = {"model": ai[-1].get("model") if ai else None, "checks": len(ai),
               "flagged": sum(bool(e.get("flagged")) for e in ai),
               "errors": sum(bool(e.get("error")) for e in ai),
               "median_ms": ok_ms[len(ok_ms) // 2] if ok_ms else None}
    return {
        "mode": mode,
        "counts": {"calls": len(calls), "allowed": len(calls) - len(stopped) - len(would),
                   "stopped": len(stopped), "would_stop": len(would), "pending":sum(a["status"] == "pending" for a in appr),
                   "tools": len(tools), "held_tools": sum(t["status"] != "approved" for t in tools)},
        "approvals": appr,
        "activity": [{"ts": e["ts"], "tool": e["tool"], "decision": e["decision"],
                      "rule": e.get("rule"), "reason": e.get("reason", ""),
                      "flags": e.get("injection_flags") or [], "request_id": e.get("request_id"),
                      "args": json.dumps(e.get("args", {}))[:160]} for e in reversed(calls[-150:])],
        "tools": tools,
        "ai": ai_info,
        "policy": plain_english(propose_policy(events)).splitlines()[1:],
    }


class _Server(ThreadingHTTPServer):
    """Refuses to share a port (fix 22 Nov: on Windows two dashboards silently shared 8770 and the
    browser reached the old one)."""
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_handler(sd: Path, token: str, port: int | None = None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the terminal quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Token", ""), token)

        def _host_ok(self) -> bool:
            # Only answer to this computer's own names (fix 22 Nov: blocks DNS-rebinding pages that
            # point a domain at 127.0.0.1; the token already stops plain cross-site requests).
            host = (self.headers.get("Host") or "").lower()
            name, _, p = host.rpartition(":") if ":" in host else (host, "", "")
            return name in ("127.0.0.1", "localhost") and (port is None or p == str(port))

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, b'{"error":"bad host"}')
            u = urlparse(self.path)
            if u.path == "/":
                if parse_qs(u.query).get("t", [""])[0] != token:
                    return self._send(403, b"Open the link printed in the terminal (it contains the access token).",
                                      "text/plain; charset=utf-8")
                return self._send(200, HTML.read_bytes(), "text/html; charset=utf-8")
            if u.path == "/api/state":
                if not self._authed():
                    return self._send(403, b'{"error":"bad token"}')
                return self._send(200, json.dumps(build_state(sd)).encode())
            self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, b'{"error":"bad host"}')
            if not self._authed():
                return self._send(403, b'{"error":"bad token"}')
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, b'{"error":"bad json"}')
            path = urlparse(self.path).path
            if path in ("/api/approve", "/api/deny"):
                ok = ApprovalStore(sd / "approvals.json", 60).decide(str(body.get("id", "")), path.endswith("approve"))
                return self._send(200 if ok else 404, json.dumps({"ok": ok}).encode())
            if path == "/api/approve-tool":
                pins = PinStore(sd / "pins.json")
                tool = str(body.get("tool", ""))
                if tool not in pins.pins:
                    return self._send(404, b'{"ok":false}')
                pins.approve(tool)
                return self._send(200, b'{"ok":true}')
            self._send(404, b'{"error":"not found"}')

    return H


def run_ui(sd: Path, port: int = 8770, open_browser: bool = True) -> None:
    sd.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(16)
    try:
        srv = _Server(("127.0.0.1", port), make_handler(sd, token, port))
    except OSError:
        raise SystemExit(f"Port {port} is already in use (is another dashboard open?). "
                         f"Close it, or run: python run_toolwarden.py ui --port {port + 1}")
    url = f"http://127.0.0.1:{port}/?t={token}"
    print(f"ToolWarden dashboard: {url}\nReading state from {sd}\nPress Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
