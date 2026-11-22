"""Command line: run the guard, manage approvals and pins, and print reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import anyio

from .policy import load_policy
from .report import load_events, plain_english, propose_policy, shadow_report
from .state import ApprovalStore, PinStore

DEFAULT_STATE = Path.home() / ".toolwarden"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="toolwarden")
    ap.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the guard as an MCP server over stdio")
    run.add_argument("--policy", required=True)
    sub.add_parser("approvals", help="list pending approval requests")
    for name in ("approve", "deny"):
        p = sub.add_parser(name, help=f"{name} an approval request")
        p.add_argument("request_id")
    sub.add_parser("pins", help="list tool pins")
    p = sub.add_parser("approve-tool", help="approve a held tool")
    p.add_argument("tool")
    sub.add_parser("report", help="session report")
    ui = sub.add_parser("ui", help="open the local admin dashboard")
    ui.add_argument("--port", type=int, default=8770)
    ui.add_argument("--no-browser", action="store_true")
    sub.add_parser("propose", help="proposed least-privilege policy")
    a = ap.parse_args(argv)
    sd: Path = a.state_dir

    if a.cmd == "run":
        from .proxy import serve
        anyio.run(serve, load_policy(a.policy), sd)
    elif a.cmd == "approvals":
        print(json.dumps(ApprovalStore(sd / "approvals.json", 60).pending(), indent=2))
    elif a.cmd in ("approve", "deny"):
        ok = ApprovalStore(sd / "approvals.json", 60).decide(a.request_id, a.cmd == "approve")
        print(f"{a.cmd}d {a.request_id}" if ok else f"no such request {a.request_id}")
    elif a.cmd == "pins":
        print(json.dumps(PinStore(sd / "pins.json").pins, indent=2))
    elif a.cmd == "approve-tool":
        PinStore(sd / "pins.json").approve(a.tool)
        print(f"approved tool {a.tool}")
    elif a.cmd == "ui":
        from .ui import run_ui
        run_ui(sd, a.port, not a.no_browser)
    elif a.cmd == "report":
        print(shadow_report(load_events(sd / "events.jsonl")))
    elif a.cmd == "propose":
        prop = propose_policy(load_events(sd / "events.jsonl"))
        print(plain_english(prop))
        print("\n" + json.dumps(prop, indent=2))


if __name__ == "__main__":
    main()
