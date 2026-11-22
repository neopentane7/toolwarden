"""Run the test set through the full ToolWarden pipeline and score it.

Each case starts a fresh guard (real proxy process, enforce mode) in front of four local tool
servers: files (demo/testset/data), web (canned pages in demo/testset/web), email (fake outbox)
and helper (a third-party stand-in). A scripted agent performs the case's steps; the guard
decides each call with the rules and, if Ollama is running, the AI reviewer.

    python demo/testset/run_testset.py              rules + AI reviewer
    python demo/testset/run_testset.py --no-ai      rules only, for comparison
    python run_toolwarden.py --state-dir demo/testset/state ui     see it all in the dashboard
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import sys
import time
from pathlib import Path

import anyio
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

from mcp import Client, StdioServerParameters  # noqa: E402

from toolwarden.judge import Judge  # noqa: E402


def text_of(r) -> str:
    return "\n".join(getattr(c, "text", "") or "" for c in (r.content or []))


def write_policy(state: Path, out: Path, ai: dict | None) -> Path:
    py = sys.executable
    servers = {
        "files": {"command": py, "args": [str(ROOT / "demo/servers/files_server.py"), str(HERE / "data")]},
        "web": {"command": py, "args": [str(ROOT / "demo/servers/web_server.py"), str(HERE / "web"), str(out)]},
        "email": {"command": py, "args": [str(ROOT / "demo/servers/email_server.py"), str(out)]},
        "helper": {"command": py, "args": [str(HERE / "helper_server.py"), str(out)]},
    }
    pol = {"mode": "enforce", "servers": servers}
    if ai:
        pol["ai_reviewer"] = ai
    p = state / "policy.yaml"
    p.write_text(yaml.safe_dump(pol), encoding="utf-8")
    return p


def layer_of(rule: str) -> str:
    if rule.startswith("pin."):
        return "pin"
    if rule.startswith("ai."):
        return "AI"
    if rule.startswith("approval."):
        return "approval"
    return "rules"


async def run_case(case: dict, policy: Path, state: Path) -> dict:
    params = StdioServerParameters(command=sys.executable, args=[
        str(ROOT / "run_toolwarden.py"), "--state-dir", str(state), "run", "--policy", str(policy)])
    got, rule, at_step, leaked = "allow", "", None, False
    t = time.perf_counter()
    async with Client(params, mode="legacy") as c:
        await c.list_tools()
        for i, step in enumerate(case["steps"], 1):
            r = await c.call_tool(step["tool"], step.get("args", {}))
            msg = text_of(r)
            stopped = r.is_error and msg.startswith("ToolWarden")
            if stopped:
                m = re.search(r"\(([^)]+)\)", msg)
                rule = m.group(1) if m else "?"
                got = "held" if "Approval request" in msg else "blocked"
                at_step = i
                break  # the agent was told to stop and tell the user
            if step.get("exfil"):
                leaked = True
    return {"got": got, "rule": rule, "step": at_step, "leaked": leaked,
            "secs": time.perf_counter() - t}


async def main(a) -> None:
    state, out = Path(a.state_dir), HERE / "out"
    for d in (state, out):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)

    ai = None
    if not a.no_ai:
        probe = Judge(a.url, a.model, 60).check_injection("hello")
        if probe.error:
            print(f"AI reviewer unavailable ({probe.error}); running rules only.\n"
                  f"Start Ollama to include it.\n")
        else:
            ai = {"enabled": True, "url": a.url, "model": a.model, "timeout_s": 60}
    policy = write_policy(state, out, ai)
    cases = yaml.safe_load((HERE / "cases.yaml").read_text(encoding="utf-8"))
    if a.only:
        cases = [c for c in cases if a.only.lower() in c["name"].lower()]

    print(f"ToolWarden test set: {len(cases)} cases, enforce mode, "
          f"{'rules + AI reviewer (' + a.model + ')' if ai else 'rules only'}\n")
    print(f"{'Case':44} {'Kind':7} {'Expect':6} {'Got':8} {'Caught by':9} {'Data out':8} Pass")
    rows = []
    for case in cases:
        r = await run_case(case, policy, state)
        stop = r["got"] != "allow"
        ok = stop == (case["expect"] == "stop")
        by = layer_of(r["rule"]) if stop else "-"
        out_col = ("YES" if r["leaked"] else "no") if case["kind"] == "attack" else "-"
        print(f"{case['name'][:44]:44} {case['kind']:7} {case['expect']:6} {r['got']:8} {by:9} "
              f"{out_col:8} {'PASS' if ok else 'FAIL'}")
        if case.get("note") and (r["leaked"] or case["kind"] == "benign"):
            print(f"{'':44}   note: {case['note']}")
        rows.append({"case": case["name"], "kind": case["kind"], "expect": case["expect"],
                     "got": r["got"], "rule": r["rule"], "caught_by": by, "stopped_at_step": r["step"],
                     "data_out": r["leaked"], "pass": ok, "seconds": round(r["secs"], 2)})

    attacks = [r for r in rows if r["kind"] == "attack"]
    benign = [r for r in rows if r["kind"] == "benign"]
    stopped = [r for r in attacks if r["got"] != "allow"]
    by = {k: sum(r["caught_by"] == k for r in stopped) for k in ("rules", "AI", "pin")}
    allow_expected = [r for r in benign if r["expect"] == "allow"]
    false_alarms = [r for r in allow_expected if r["got"] != "allow"]
    print(f"\nAttacks stopped: {len(stopped)}/{len(attacks)}  "
          f"(rules {by['rules']}, AI reviewer {by['AI']}, tool pinning {by['pin']})")
    print(f"Attacks where some data still got out: {sum(r['data_out'] for r in attacks)}/{len(attacks)}")
    print(f"Normal tasks allowed: {len(allow_expected) - len(false_alarms)}/{len(allow_expected)}"
          f"   false alarms: {len(false_alarms)}"
          + "".join(f"\n  false alarm: {r['case']} ({r['rule']})" for r in false_alarms))
    asks = [r for r in benign if r["expect"] == "stop"]
    if asks:
        print(f"Normal tasks that ask first by design: {sum(r['got'] != 'allow' for r in asks)}/{len(asks)}")
    secs = sorted(r["seconds"] for r in rows)
    print(f"Median time per case (starting the guard included): {secs[len(secs) // 2]:.1f} s")
    print(f"Passed: {sum(r['pass'] for r in rows)}/{len(rows)}")

    with (out / "results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"\nSaved {out / 'results.csv'}")
    print(f"What the fake attacker received: {out}  (outbox.jsonl, web_requests.log, helper_calls.log)")
    print(f"See every call in the dashboard:\n  python run_toolwarden.py --state-dir {state} ui")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-ai", action="store_true", help="rules only")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--url", default="http://127.0.0.1:11434")
    ap.add_argument("--state-dir", default=str(HERE / "state"))
    ap.add_argument("--only", help="run only cases whose name contains this text")
    anyio.run(main, ap.parse_args())
