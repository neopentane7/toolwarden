"""On-disk state: tool pins, approvals, sessions and the redacted event log."""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path


def tool_hash(name: str, description: str | None, schema: dict | None) -> str:
    blob = json.dumps({"n": name, "d": description or "", "s": schema or {}}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic on Windows and POSIX


class PinStore:
    """Remembers the approved definition of every tool (trust on first use, with holds).

    Status values: approved, held_changed (definition changed since approval: possible rug pull),
    held_suspicious (description looks like tool poisoning; needs an admin before first use).
    """

    def __init__(self, path: Path):
        self.path = path
        self.pins: dict[str, dict] = _read_json(path, {})

    def check(self, key: str, h: str, suspicious: bool, hold_suspicious: bool,
              hold_changed: bool) -> str:
        # Re-read from disk: an admin may have approved a held tool from the command line
        # while the guard is running (bug fixed 19 Nov: approvals were ignored until restart).
        self.pins = _read_json(self.path, self.pins)
        pin = self.pins.get(key)
        if pin is None:
            status = "held_suspicious" if (suspicious and hold_suspicious) else "approved"
            self.pins[key] = {"hash": h, "status": status, "first_seen": time.time()}
            _write_json(self.path, self.pins)
            return status
        if pin["hash"] != h and hold_changed and pin["status"] == "approved":
            pin.update(status="held_changed", new_hash=h, changed_at=time.time())
            _write_json(self.path, self.pins)
        elif pin["status"] == "held_changed" and pin["hash"] == h:
            # The server went back to the exact definition that was approved: safe to use
            # again (bug fixed 19 Nov: reverted tools stayed blocked forever).
            pin["status"] = "approved"
            pin.pop("new_hash", None)
            _write_json(self.path, self.pins)
        elif pin["status"] == "held_changed" and pin.get("new_hash") != h:
            pin["new_hash"] = h  # changed again: the admin reviews the latest version
            _write_json(self.path, self.pins)
        return pin["status"]

    def approve(self, key: str) -> None:
        self.pins = _read_json(self.path, self.pins)
        pin = self.pins[key]
        pin["hash"] = pin.pop("new_hash", pin["hash"])
        pin["status"] = "approved"
        _write_json(self.path, self.pins)


class ApprovalStore:
    """Block-then-retry approvals. The guard writes a pending request; an admin approves or
    denies it (command line now, Telegram or a web page later); the identical retry then passes."""

    def __init__(self, path: Path, ttl_minutes: float):
        self.path = path
        self.ttl = ttl_minutes * 60

    @staticmethod
    def request_id(tool_key: str, args: dict) -> str:
        blob = tool_key + json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:10]

    def _load(self) -> dict:
        return _read_json(self.path, {})

    def status(self, rid: str) -> str | None:
        rec = self._load().get(rid)
        if not rec:
            return None
        now = time.time()
        if rec["status"] in ("approved", "denied") and now - rec.get("decided_at", 0) > self.ttl:
            return "expired"
        if rec["status"] == "pending" and now - rec.get("created_at", 0) > self.ttl:
            return "expired"  # nobody answered in time; a new attempt files a fresh request
        return rec["status"]

    def granted(self, rid: str, tool_key: str, rule: str, session: str | None = None) -> bool:
        """Approved if this exact request was approved, or a request for the same tool and
        rule in the same session was approved within the time limit. Models rarely retry with
        identical wording (bug fixed 19 Nov: approved actions were blocked again on retry).
        Limited to one session so an approval does not open the door for later attacks."""
        if self.status(rid) == "approved":
            return True
        now = time.time()
        return any(r["status"] == "approved" and r["tool"] == tool_key and r["rule"] == rule
                   and session is not None and r.get("session") == session
                   and now - r.get("decided_at", 0) <= self.ttl for r in self._load().values())

    def request(self, rid: str, tool_key: str, rule: str, preview: str,
                session: str | None = None) -> None:
        data = self._load()
        # Re-file if the old request expired (fix 19 Nov audit: the model was told a request had
        # been sent while nothing new appeared for the admin).
        if rid not in data or self.status(rid) == "expired":
            data[rid] = {"status": "pending", "tool": tool_key, "rule": rule, "session": session,
                         "preview": preview, "created_at": time.time()}
            _write_json(self.path, data)

    def decide(self, rid: str, approve: bool) -> bool:
        data = self._load()
        if rid not in data or self.status(rid) != "pending":
            return False  # only open requests can be decided
        data[rid].update(status="approved" if approve else "denied", decided_at=time.time())
        _write_json(self.path, data)
        return True

    def pending(self) -> dict:
        return {k: v for k, v in self._load().items() if self.status(k) == "pending"}


@dataclass
class Session:
    """What the agent has seen recently. MCP gives the proxy no chat id, so a session is one
    proxy run plus an inactivity window (see the plan's audit)."""
    sid: str
    last_ts: float
    saw_untrusted: bool = False
    saw_private: bool = False
    injection_seen: bool = False  # an untrusted result looked like it was giving the agent orders
    private_segments: set[str] = field(default_factory=set)
    private_text: str = ""  # raw private results, for the AI reviewer (judge.focus picks lines)
    # Text already sent out per "tool:field", to catch secrets split across several calls.
    outbound_by_field: dict[str, str] = field(default_factory=dict)


class SessionTracker:
    def __init__(self, idle_minutes: float):
        self.idle = idle_minutes * 60
        self.run_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]
        self.count = 0
        self.current: Session | None = None

    def get(self, now: float | None = None) -> Session:
        now = now or time.time()
        if self.current is None or now - self.current.last_ts > self.idle:
            self.count += 1
            self.current = Session(sid=f"{self.run_id}-{self.count}", last_ts=now)
        self.current.last_ts = now
        return self.current


def private_segments(text: str, min_len: int) -> set[str]:
    """Pieces of private output worth tracking: whole lines and long tokens (keys, ids)."""
    import re
    segs = set()
    for line in text.splitlines():
        line = line.strip()
        if len(line) >= min_len:
            segs.add(line)
        # Split on whitespace and on KEY=value / key: value separators, so that sending only
        # the value of "FAKE_API_KEY=sk-..." is still caught.
        for tok in re.split(r"[\s=:,;\"'`]+", line):
            if len(tok) >= min_len:
                segs.add(tok)
    return segs


class EventLog:
    """JSON Lines audit log. Known private content is redacted before anything is written."""

    def __init__(self, path: Path):
        self.path = path

    def write(self, event: dict, redact: set[str] = frozenset()) -> None:
        event = {"ts": round(time.time(), 3), **event}
        line = json.dumps(event, default=str)
        for seg in sorted(redact, key=len, reverse=True):
            line = line.replace(json.dumps(seg)[1:-1], "[REDACTED]")
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
