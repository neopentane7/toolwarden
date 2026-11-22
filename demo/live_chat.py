"""Live, unscripted demo: chat with a local AI model (Ollama) that uses real MCP tools,
with ToolWarden in between. You type; the model decides every tool call; the guard decides
live whether each call goes through.

Run:   python demo/live_chat.py --model qwen2.5:7b
Commands while chatting:
  /guard on | /guard off   switch ToolWarden on or off (restarts the tools)
  /shadow | /enforce       switch guard mode
  /approvals               list pending approval requests
  /approve <id>            approve a request (then ask the model to try again)
  /rugpull                 make the calculator tool change its description (rug pull)
  /report                  shadow report from this session's real log
  /outbox                  show what the fake email server actually sent
  /reset                   clear the conversation
  /quit
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path

import anyio
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import llm_eval as ev  # noqa: E402
from toolwarden.report import load_events, plain_english, propose_policy, shadow_report  # noqa: E402
from toolwarden.state import ApprovalStore  # noqa: E402

FLAG = ev.DEMO / "data" / "RUGPULL"


class LiveTools(ev.Tools):
    def __init__(self, guarded: bool, state_dir: Path, mode: str, policy_path: Path, ai: dict | None = None):
        super().__init__(guarded, state_dir, policy_path)
        self.mode, self.ai = mode, ai

    async def open(self, stack):
        if not self.guarded:
            return await super().open(stack)
        pol = yaml.safe_load(self.policy_path.read_text())
        pol["mode"] = self.mode
        if self.ai:
            pol["ai_reviewer"] = {**pol.get("ai_reviewer", {}), **self.ai}
        base = self.policy_path.parent
        for s in pol["servers"].values():
            s["args"] = [str(base / a) if (base / a).exists() else a for a in s["args"]]
        p = self.sd / "policy.yaml"
        p.write_text(yaml.safe_dump(pol))
        params = ev.StdioServerParameters(command=sys.executable, args=[
            str(ev.ROOT / "run_toolwarden.py"), "--state-dir", str(self.sd), "run", "--policy", str(p)])
        self.clients["guard"] = await stack.enter_async_context(ev.Client(params, mode="legacy"))
        self.tools = [(t, "guard", t.name) for t in (await self.clients["guard"].list_tools()).tools]


def banner(tools: LiveTools):
    state = f"ON ({tools.mode})" if tools.guarded else "OFF"
    print(f"\n=== ToolWarden {state} | tools the model can see: "
          f"{', '.join(t['function']['name'] for t in tools.schema())}\n")


async def chat_loop(a):
    sd = Path(a.state_dir) if a.state_dir else Path(tempfile.mkdtemp(prefix="tw-live-"))
    sd.mkdir(parents=True, exist_ok=True)
    ai = {"enabled": True, "model": a.model, "url": a.host} if a.ai else None
    print(f"Guard state folder (open it in the dashboard): {sd}")
    if ai:
        print(f"AI reviewer on: {a.model}")
    guarded, mode = True, "enforce"
    chat = ev.mock_chat if a.mock else ev.ollama_chat
    msgs = [{"role": "system", "content": ev.SYSTEM}]
    ev._clear()
    FLAG.unlink(missing_ok=True)
    lines = sys.stdin if a.mock else None

    while True:
        async with AsyncExitStack() as stack:
            tools = LiveTools(guarded, sd, mode, Path(a.policy), ai)
            await tools.open(stack)
            banner(tools)
            restart = False
            while not restart:
                try:
                    user = (next(lines).rstrip("\n") if lines else input("You> ")).strip()
                except (EOFError, StopIteration):
                    return
                if not user:
                    continue
                cmd = user.split()
                if cmd[0] == "/quit":
                    return
                # Switching guard state or resetting starts a clean conversation AND a fresh guard
                # session, so one demo cannot taint the next (bug fixed 19 Nov).
                if cmd[0] == "/guard" and len(cmd) > 1:
                    guarded, restart, msgs = cmd[1] == "on", True, msgs[:1]
                    continue
                if cmd[0] in ("/shadow", "/enforce"):
                    mode, restart, msgs = cmd[0][1:], True, msgs[:1]
                    continue
                if cmd[0] == "/reset":
                    msgs, restart = msgs[:1], True
                    ev._clear()
                    FLAG.unlink(missing_ok=True)
                    print("(conversation, guard session and fake outbox cleared)")
                    continue
                if cmd[0] == "/rugpull":
                    FLAG.write_text("on")
                    print("(calculator server now serves a changed 'add' description)")
                    continue
                if cmd[0] == "/approvals":
                    print(json.dumps(ApprovalStore(sd / "approvals.json", 60).pending(), indent=2))
                    continue
                if cmd[0] == "/approve" and len(cmd) > 1:
                    ok = ApprovalStore(sd / "approvals.json", 60).decide(cmd[1], True)
                    print("(approved - ask the model to try again)" if ok else "(no such request)")
                    continue
                if cmd[0] == "/report":
                    ev_ = load_events(sd / "events.jsonl")
                    print(shadow_report(ev_))
                    print(plain_english(propose_policy(ev_)))
                    continue
                if cmd[0] == "/outbox":
                    print(ev._read(ev.OUTBOX) or "(nothing sent)")
                    continue

                msgs.append({"role": "user", "content": user})
                for _ in range(8):
                    try:
                        msg = chat(a.host, a.model, msgs, tools.schema())
                    except Exception as e:  # noqa: BLE001
                        print(f"[model error] {e}. Is 'ollama serve' running?")
                        msgs.pop()
                        break
                    msgs.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
                    tcs = msg.get("tool_calls") or []
                    if not tcs:
                        print(f"\nAI> {msg.get('content', '')}\n")
                        break
                    for tc in tcs:
                        fn = tc["function"]
                        args = fn.get("arguments") or {}
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except json.JSONDecodeError:
                                args = {}
                        print(f"  [tool call] {fn['name']} {json.dumps(args)[:150]}")
                        out, blocked = await tools.call(fn["name"], args)
                        if blocked:
                            print(f"  [BLOCKED]   {out[:220]}")
                        elif ev.is_exfil_attempt(fn["name"], args):
                            print("  [!] call aimed at the attacker went through")
                        msgs.append({"role": "tool", "tool_name": fn["name"], "content": out})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--policy", default=str(ev.ROOT / "policy.example.yaml"),
                    help="policy.example.yaml (demo tools) or policy.real.yaml (real folder and web)")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--ai", action="store_true", help="turn on the AI reviewer (uses the same Ollama model)")
    ap.add_argument("--state-dir", help="keep guard state here, e.g. to watch it in the dashboard")
    ap.add_argument("--mock", action="store_true", help="fake model reading commands from stdin (testing)")
    anyio.run(chat_loop, ap.parse_args())
