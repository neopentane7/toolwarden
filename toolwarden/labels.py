"""Rule-based risk labels for MCP tools.

Labels describe what a tool can do (private, untrusted, outbound, destructive).
"suspicious" means the tool's own description looks like an attack (tool poisoning).
Rules are deliberately simple and explainable; a local model can refine them later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PRIVATE = ["read_file", "read", "file", "inbox", "mailbox", "database", "query", "secret",
           "password", "credential", "contacts", "calendar", "notes", "document", "drive"]
UNTRUSTED = ["fetch", "url", "web", "browse", "search", "http", "scrape", "rss", "issue",
             "ticket", "comment", "forum", "social", "page"]
OUTBOUND = ["send", "post", "upload", "publish", "share", "submit", "forward", "webhook",
            "tweet", "reply", "notify", "message"]
DESTRUCTIVE = ["delete", "remove", "drop", "overwrite", "truncate", "transfer", "pay", "payment",
               "execute", "exec", "shell", "kill", "terminate", "wipe", "destroy"]
# Creating something public (an issue, a comment, a post) sends data out even though the verb
# is "create": e.g. create_github_issue.
PUBLISH_VERBS = {"create", "add", "open", "write", "update", "make", "new"}
PUBLIC_OBJECTS = {"issue", "comment", "post", "pr", "pull", "tweet", "message", "gist", "review",
                  "discussion", "status"}


def name_tokens(name: str) -> list[str]:
    """Split snake_case, kebab-case, dotted and camelCase names into lowercase words."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]

POISON_PATTERNS = [
    (r"<\s*important\s*>", "hidden <IMPORTANT> block"),
    (r"ignore (all |any )?(previous|prior) instructions", "asks the model to ignore instructions"),
    (r"(do not|don't|never) (tell|mention|inform|show)", "asks the model to hide something from the user"),
    (r"before (using|calling) (this|any) tool", "instructions to run before the tool"),
    (r"~/\.ssh|id_rsa|\.env\b|mcp\.json|\.aws/credentials", "references secret files"),
    (r"[​‌‍⁠﻿]", "invisible characters"),
    (r"[A-Za-z0-9+/]{120,}={0,2}", "long encoded blob"),
]


@dataclass
class ToolLabels:
    labels: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return "suspicious" in self.labels


def _words(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9_~./]+", " ", text.lower()) + " "


def label_tool(name: str, description: str | None, schema: dict | None,
               other_tool_names: set[str] | None = None) -> ToolLabels:
    desc = description or ""
    toks = name_tokens(name)
    text = _words(desc)
    out = ToolLabels()

    def hit(keys: list[str]) -> bool:
        # Whole words only (bug fixed 19 Nov: substring matching marked format_date as
        # destructive, postgres_query as outbound, list_skills as destructive and
        # thread_summary as private). A name word may extend a keyword: fetch -> fetcher.
        in_name = any(t == k or (len(k) >= 5 and t.startswith(k)) for t in toks for k in keys)
        return in_name or any(f" {k} " in text for k in keys)

    # Outbound and destructive verbs are checked on the name first: "send_email" must not
    # also count as private just because its description says "email".
    if hit(OUTBOUND) or (PUBLISH_VERBS & set(toks) and PUBLIC_OBJECTS & set(toks)):
        out.labels.add("outbound")
    if hit(DESTRUCTIVE):
        out.labels.add("destructive")
    if hit(UNTRUSTED):
        out.labels.add("untrusted")
    if hit(PRIVATE) and "outbound" not in out.labels:
        out.labels.add("private")

    for pattern, reason in POISON_PATTERNS:
        if re.search(pattern, desc, flags=re.IGNORECASE):
            out.labels.add("suspicious")
            out.reasons.append(reason)

    # Extra schema parameters that look like covert channels (Invariant's "sidenote" example).
    props = (schema or {}).get("properties", {}) or {}
    for p in props:
        if p.lower() in {"sidenote", "note", "context", "metadata", "debug"} and "suspicious" in out.labels:
            out.reasons.append(f"possible covert parameter '{p}'")

    # Cross-server shadowing: the description talks about another server's tools.
    for other in other_tool_names or set():
        short = other.split("__", 1)[-1]
        if short != name and len(short) > 3 and re.search(rf"\b{re.escape(short)}\b", desc):
            out.labels.add("suspicious")
            out.reasons.append(f"mentions another tool '{short}'")
    return out
