"""The guard itself: one MCP server facing the agent app, one MCP client per real server.

Tool names are exposed as "<server>__<tool>". Every call is re-checked against the tool's
current definition, because agent apps cache tool lists (a rug-pulled tool would otherwise
still be callable; this was found in the 18 Nov spike).
"""

from __future__ import annotations

import re
from contextlib import AsyncExitStack
from pathlib import Path

import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

import anyio

from .engine import Decision, block_message, decide
from .judge import Judge
from .labels import POISON_PATTERNS, label_tool
from .policy import Policy
from .state import (ApprovalStore, EventLog, PinStore, SessionTracker, private_segments,
                    tool_hash)

SEP = "__"


def _text_of(result) -> str:
    return "\n".join(getattr(c, "text", "") or "" for c in (result.content or []))


def strong_injection_flags(text: str) -> list[str]:
    return [r for p, r in POISON_PATTERNS if re.search(p, text, re.IGNORECASE)]


def weak_injection_flags(text: str) -> list[str]:
    """Loose pattern: also matches pages that merely talk about emailing keys (a security blog)."""
    if re.search(r"(email|send|forward|upload).{0,80}(secret|password|key|file)", text, re.I):
        return ["response asks the agent to send data out"]
    return []


def rule_injection_flags(text: str) -> list[str]:
    """Pattern-based check of an untrusted result for instructions aimed at the agent."""
    return strong_injection_flags(text) + weak_injection_flags(text)


class Guard:
    def __init__(self, policy: Policy, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.pins = PinStore(state_dir / "pins.json")
        self.approvals = ApprovalStore(state_dir / "approvals.json", policy.approval_ttl_minutes)
        self.log = EventLog(state_dir / "events.jsonl")
        self.sessions = SessionTracker(policy.session_idle_minutes)
        self.clients: dict[str, Client] = {}
        self.catalog: dict[str, dict] = {}
        ai = policy.ai_reviewer
        self.judge = Judge(ai.url, ai.model, ai.timeout_s) if ai.enabled else None

    async def connect(self, stack: AsyncExitStack) -> None:
        for name, spec in self.policy.servers.items():
            command, args = self.policy.resolve_server(spec)
            params = StdioServerParameters(command=command, args=args, env=spec.env)
            self.clients[name] = await stack.enter_async_context(Client(params, mode="legacy"))

    async def refresh(self, only: str | None = None) -> None:
        listed: dict[str, list] = {}
        for server, client in self.clients.items():
            if only and server != only:
                continue
            listed[server] = (await client.list_tools()).tools
        all_names = {f"{s}{SEP}{t.name}" for s, ts in listed.items() for t in ts} | set(self.catalog)
        for server, tools in listed.items():
            others = {n for n in all_names if not n.startswith(server + SEP)}
            for t in tools:
                key = f"{server}{SEP}{t.name}"
                lab = label_tool(t.name, t.description, t.input_schema, others)
                labels = set(self.policy.label_overrides.get(key, lab.labels))
                status = self.pins.check(key, tool_hash(t.name, t.description, t.input_schema),
                                         lab.suspicious, self.policy.rules.hold_suspicious_tools,
                                         self.policy.rules.hold_changed_tools)
                prev = self.catalog.get(key)
                self.catalog[key] = {"server": server, "tool": t, "labels": labels,
                                     "reasons": lab.reasons, "status": status}
                if prev is None or prev["status"] != status:
                    self.log.write({"event": "tool_seen", "tool": key, "labels": sorted(labels),
                                    "status": status, "reasons": lab.reasons})

    async def list_tools(self, ctx, params) -> types.ListToolsResult:
        await self.refresh()
        out = []
        for key, info in self.catalog.items():
            if self.policy.mode == "enforce" and info["status"] != "approved":
                continue
            t = info["tool"]
            out.append(types.Tool(name=key, description=t.description,
                                  input_schema=t.input_schema))
        return types.ListToolsResult(tools=out)

    def _log_ai(self, check: str, key: str, session, v) -> None:
        self.log.write({"event": "ai_review", "check": check, "tool": key, "session": session.sid,
                        "flagged": v.flagged, "what": v.what, "ms": round(v.ms), "error": v.error,
                        "model": getattr(self.judge, "model", None)},
                       session.private_segments)

    async def ai_leak_check(self, d: Decision, key: str, labels: set, args: dict, session) -> Decision:
        """Second opinion on calls the rules allowed. Can only make the decision stricter."""
        if (d.action != "allow" or d.rule == "approval.granted" or not self.judge
                or not self.policy.ai_reviewer.check_leaks or not labels & {"outbound", "untrusted"}
                or not session.private_text):
            return d
        v = await anyio.to_thread.run_sync(self.judge.check_leak, session.private_text, key, args)
        self._log_ai("leak", key, session, v)
        if not v.flagged:
            return d
        rule, reason = "ai.reworded_leak", f"AI reviewer: {v.what or 'reveals a secret read earlier'}"
        if session.injection_seen:
            return Decision("block", rule + "+injection",
                            reason + "; an untrusted page or result in this session contained instructions")
        rid = self.approvals.request_id(key, args)
        if self.approvals.status(rid) == "denied":
            return Decision("block", "approval.denied", f"an administrator denied request {rid}", rid)
        if self.approvals.granted(rid, key, rule, session.sid):
            return Decision("allow", "approval.granted", f"approved request {rid}", rid)
        return Decision("approval_requested", rule, reason, rid)

    async def call_tool(self, ctx, params) -> types.CallToolResult:
        key, args = params.name, dict(params.arguments or {})
        session = self.sessions.get()
        server = key.split(SEP, 1)[0]
        if server in self.clients:
            await self.refresh(only=server)  # re-check the definition at call time
        info = self.catalog.get(key)
        if info is None:
            self.log.write({"event": "call", "session": session.sid, "tool": key,
                            "decision": "block", "rule": "unknown_tool"})
            return _error(f"ToolWarden: unknown tool {key}.")

        d = decide(self.policy, key, info["labels"], info["status"], args, session, self.approvals)
        d = await self.ai_leak_check(d, key, info["labels"], args, session)
        redact = session.private_segments
        base = {"event": "call", "session": session.sid, "tool": key, "args": args,
                "rule": d.rule, "reason": d.reason, "mode": self.policy.mode}

        if d.action != "allow":
            if d.action == "approval_requested" and self.policy.mode == "enforce":
                # Shadow mode never blocks, so it files no requests (bug fixed 19 Nov).
                preview = f"{key} ({d.rule})"  # no arguments: requests may leave the machine
                self.approvals.request(d.request_id, key, d.rule, preview, session.sid)
            if self.policy.mode == "enforce":
                self.log.write({**base, "decision": d.action, "request_id": d.request_id}, redact)
                return _error(block_message(d))
            self.log.write({**base, "decision": "would_block", "would": d.action,
                            "request_id": d.request_id}, redact)

        # Remember what actually went out, for split-secret checks. Blocked calls are not
        # recorded (fix 19 Nov audit), since nothing left.
        for k, v in args.items():
            if isinstance(v, (str, int, float)):
                f = f"{key}:{k}"
                session.outbound_by_field[f] = (session.outbound_by_field.get(f, "") + str(v))[-2000:]

        client = self.clients[info["server"]]
        result = await client.call_tool(info["tool"].name, args)
        text = _text_of(result)
        flags = []
        if "untrusted" in info["labels"]:
            session.saw_untrusted = True
            flags = strong_injection_flags(text)
            weak = weak_injection_flags(text)
            if not flags and self.judge and self.policy.ai_reviewer.check_injection and text.strip():
                # The AI reviewer reads the page. A loose pattern match alone no longer marks the
                # session as attacked if the reviewer saw no instructions (fix 19 Nov test set:
                # a blog about key safety held a later normal email).
                v = await anyio.to_thread.run_sync(self.judge.check_injection, text)
                self._log_ai("injection", key, session, v)
                if v.flagged:
                    flags += weak + [f"AI reviewer: {v.what or 'page gives the agent instructions'}"]
                elif v.error:
                    flags += weak  # reviewer unreachable: fall back to the rules
            elif not flags:
                flags = weak
            if flags:
                session.injection_seen = True
        elif "private" in info["labels"]:
            # Files and inboxes can carry injected instructions too (a shared doc, a received
            # email). Only the strong patterns are used here, since private notes often mention
            # emailing files or passwords.
            flags = [r for p, r in POISON_PATTERNS if re.search(p, text, re.IGNORECASE)]
            if flags:
                session.injection_seen = True
        if "private" in info["labels"]:
            session.saw_private = True
            session.private_segments |= private_segments(text, self.policy.min_match_length)
            session.private_text = (session.private_text + "\n" + text)[-50000:]
        if d.action == "allow":
            self.log.write({**base, "decision": "allow", "injection_flags": flags},
                           session.private_segments)
        elif flags:
            self.log.write({"event": "response_flags", "tool": key, "flags": flags})
        return result


def _error(msg: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=msg)], is_error=True)


async def serve(policy: Policy, state_dir: Path) -> None:
    guard = Guard(policy, state_dir)
    async with AsyncExitStack() as stack:
        await guard.connect(stack)
        server = Server("toolwarden", on_list_tools=guard.list_tools, on_call_tool=guard.call_tool)
        async with stdio_server() as (r, w):
            await server.run(r, w, server.create_initialization_options())
