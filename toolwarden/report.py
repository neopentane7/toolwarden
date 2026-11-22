"""Shadow-mode report and a first proposed policy, built from the event log."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def load_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def shadow_report(events: list[dict]) -> str:
    calls = [e for e in events if e.get("event") == "call"]
    tools = {e["tool"]: e for e in events if e.get("event") == "tool_seen"}
    flagged = [e for e in calls if e["decision"] in ("would_block", "block", "approval_requested")]
    by_rule = Counter(e.get("rule") for e in flagged)
    lines = ["# ToolWarden session report", "",
             f"- Tool calls observed: {len(calls)}",
             f"- Calls that would have been stopped: {len(flagged)}",
             f"- Tools seen: {len(tools)}", ""]
    if by_rule:
        lines += ["## Would have been stopped, by rule", "", "| Rule | Calls |", "| --- | --- |"]
        lines += [f"| {r} | {n} |" for r, n in by_rule.most_common()]
        lines += ["", "## Examples", ""]
        for e in flagged[:10]:
            lines.append(f"- `{e['tool']}` - {e.get('reason', '')} (session {e.get('session')})")
    held = [k for k, e in tools.items() if e.get("status") != "approved"]
    if held:
        lines += ["", "## Tools needing review", ""]
        lines += [f"- `{k}`: {tools[k]['status']} - {', '.join(tools[k].get('reasons') or [])}"
                  for k in held]
    return "\n".join(lines) + "\n"


def propose_policy(events: list[dict]) -> dict:
    """Least-privilege proposal from what was actually used. A human must review it:
    if misuse happened while observing, it would be learned too."""
    calls = [e for e in events if e.get("event") == "call"]
    used = Counter(e["tool"] for e in calls if e["decision"] == "allow")
    seen = {e["tool"] for e in events if e.get("event") == "tool_seen"}
    risky = {e["tool"] for e in calls if e["decision"] != "allow"}
    return {
        "allow_tools": sorted(t for t in used if t not in risky),
        "disable_unused_tools": sorted(seen - set(used) - risky),
        "needs_review": sorted(risky),
        "keep_rules_on": ["pins", "provenance.private_to_outbound",
                          "chain.untrusted_private_outbound"],
    }


def plain_english(proposal: dict) -> str:
    out = ["Proposed policy (review before switching to enforce mode):"]
    for t in proposal["allow_tools"]:
        out.append(f"- Allow {t}: it was used normally while observing.")
    for t in proposal["disable_unused_tools"]:
        out.append(f"- Turn off {t}: it was never used.")
    for t in proposal["needs_review"]:
        out.append(f"- Review {t}: some of its calls would have been stopped.")
    out.append("- Always ask before sending out data that came from private tools.")
    return "\n".join(out)
