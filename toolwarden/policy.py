"""Policy file: which servers to guard, which mode to run in, and which rules are on."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    # A typo such as 'ai_reviwer' must fail loudly, not silently leave a check off (fix 19 Nov audit).
    model_config = ConfigDict(extra="forbid")


class ServerSpec(_Strict):
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] | None = None


class Rules(_Strict):
    hold_changed_tools: bool = True
    hold_suspicious_tools: bool = True
    provenance_private_to_outbound: bool = True
    chain_untrusted_private_outbound: bool = True
    # True: the chain rule only fires if an untrusted result looked like instructions.
    # False: any untrusted + private + outbound sequence asks for approval (stricter, more prompts).
    chain_requires_injection: bool = True


class AIReviewer(_Strict):
    """Optional local LLM second opinion (see judge.py). Off unless enabled."""
    enabled: bool = False
    url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b"
    timeout_s: float = 30
    check_leaks: bool = True       # reworded / spelled-out secrets in outgoing calls
    check_injection: bool = True   # instructions hidden in web pages and other untrusted results


class Policy(_Strict):
    mode: Literal["shadow", "enforce"] = "shadow"
    session_idle_minutes: float = 30
    min_match_length: int = 10
    approval_ttl_minutes: float = 60
    servers: dict[str, ServerSpec]
    rules: Rules = Field(default_factory=Rules)
    ai_reviewer: AIReviewer = Field(default_factory=AIReviewer)
    # Optional manual label fixes, keyed "server__tool" -> list of labels.
    label_overrides: dict[str, list[str]] = Field(default_factory=dict)
    base_dir: Path = Path(".")

    def resolve_server(self, spec: ServerSpec) -> tuple[str, list[str]]:
        """Resolve 'python' to this interpreter and make relative script paths absolute.

        Agent apps often start the guard from an unexpected working folder, so every path
        in the policy is taken relative to the policy file, not the current folder.
        """
        command = sys.executable if spec.command in ("python", "python3") else spec.command
        args = []
        for a in spec.args:
            p = self.base_dir / a
            args.append(str(p) if (not os.path.isabs(a) and p.exists()) else a)
        return command, args


def load_policy(path: str | os.PathLike) -> Policy:
    path = Path(path).resolve()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data["base_dir"] = path.parent
    return Policy.model_validate(data)
