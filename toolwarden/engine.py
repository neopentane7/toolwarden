"""Decision engine: decides allow / block / approval_requested for one tool call.

In shadow mode nothing is blocked; the decision is logged as would_block instead.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .policy import Policy
from .state import ApprovalStore, Session


def searchable_text(args: dict) -> str:
    """Arguments as text, plus decoded versions of anything that looks URL-, base64- or
    hex-encoded, so simple encodings do not hide a copied secret (gap found 18 Nov)."""
    import base64
    import binascii
    import re
    from urllib.parse import unquote_plus

    raw = json.dumps(args, default=str, ensure_ascii=False)
    parts = [raw, unquote_plus(raw)]
    # '=' only as padding at the end, so "ref=<base64>" in a URL yields the base64 part on its own
    # (fix 19 Nov test set: the key=value prefix made the decode come out as garbage).
    for tok in re.findall(r"[A-Za-z0-9+/_\-]{16,}={0,2}", raw):
        for decode in (lambda t: base64.b64decode(t + "=" * (-len(t) % 4), validate=False),
                       lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)),
                       lambda t: binascii.unhexlify(t) if len(t) % 2 == 0 else b""):
            try:
                txt = decode(tok).decode("utf-8", errors="ignore")
            except (binascii.Error, ValueError):
                continue
            if sum(ch.isprintable() for ch in txt) > 0.9 * max(len(txt), 1):
                parts.append(txt)
    return "\n".join(parts)


def squash(text: str) -> str:
    """Lowercase and drop whitespace and common separators, so 'sk-demo 9f8e' and pieces glued
    from separate calls compare equal to the original."""
    import re
    return re.sub(r"[\s\"'`,;|]+", "", text).lower()


def _window_hit(secret: str, haystacks: list[str], win: int) -> bool:
    """True if any run of `win` characters from the secret was sent. Catches partial copies and
    the first pieces of a split secret, not only the complete string."""
    if len(secret) < win:
        return any(secret in h for h in haystacks)
    windows = {secret[i:i + win] for i in range(len(secret) - win + 1)}
    return any(w in h for h in haystacks for w in windows)


def alnum(text: str) -> str:
    """Letters and digits only, so 's.k.-.d.e.m.o' and 'sk -d em o' compare equal to 'sk-demo'."""
    import re
    return re.sub(r"[^0-9a-z]+", "", text.lower())


def secret_like(seg: str) -> bool:
    """A single token with a digit or of 20+ characters (keys, passwords, ids), as opposed to a
    sentence. Partial-match windows are only used on these (fix 19 Nov audit: windows over prose
    lines held ordinary emails that shared a phrase like 'in the shared drive' with a note)."""
    return not any(c.isspace() for c in seg) and (any(c.isdigit() for c in seg) or len(seg) >= 20)


@dataclass
class Decision:
    action: str          # allow | block | approval_requested
    rule: str | None = None
    reason: str = ""
    request_id: str | None = None


def decide(policy: Policy, tool_key: str, labels: set[str], pin_status: str, args: dict,
           session: Session, approvals: ApprovalStore) -> Decision:
    if pin_status != "approved":
        why = {"held_changed": "tool definition changed since approval (possible rug pull)",
               "held_suspicious": "tool description looks like tool poisoning"}.get(pin_status, pin_status)
        return Decision("block", f"pin.{pin_status}", why)

    # Provenance applies to every tool, not only ones labelled outbound (fix 19 Nov audit): a
    # poisoned tool that slips past the description check can still smuggle a secret out in an
    # extra parameter, as calc's 'sidenote' does.
    rule, reason = None, ""
    blob = searchable_text(args)
    # Split secrets: what earlier forwarded calls to the same tool and field sent, joined with
    # this call. Only the last few characters are joined (fix 19 Nov audit: joining the whole
    # history meant one blocked leak made every later email in the session look like a leak).
    win = max(policy.min_match_length, 12)
    joined = [squash(session.outbound_by_field.get(f"{tool_key}:{k}", "")[-(policy.min_match_length - 1):] + str(v))
              for k, v in args.items() if isinstance(v, (str, int, float))]
    haystacks = [blob, blob[::-1], squash(blob), squash(blob)[::-1]] + joined + [j[::-1] for j in joined]
    an = [alnum(h) for h in haystacks]
    if policy.rules.provenance_private_to_outbound and session.private_segments:
        leaked = []
        for seg in session.private_segments:
            if len(seg) < policy.min_match_length:
                continue
            if any(seg in h for h in haystacks):
                leaked.append(seg)
            elif secret_like(seg) and (_window_hit(squash(seg), haystacks, win)
                                       or _window_hit(alnum(seg), an, policy.min_match_length)):
                leaked.append(seg)
        if leaked:
            rule = "provenance.private_to_outbound"
            reason = f"call contains private content read earlier ({len(leaked)} match(es))"
    # The chain rule needs an actual injection signal: reading the web and your own files, then
    # emailing something unrelated, is normal work, not an attack.
    chain = (rule is None and policy.rules.chain_untrusted_private_outbound
             and "outbound" in labels and session.saw_untrusted and session.saw_private
             and (session.injection_seen or not policy.rules.chain_requires_injection))
    if chain:
        rule = "chain.untrusted_private_outbound"
        reason = "session read untrusted content and private data before this outbound call"
    if rule and session.injection_seen and not chain:
        # Private data found in the call AND a page tried to give orders: refuse outright
        # instead of offering an approval an admin might click through. The chain rule alone
        # (no data matched) asks a person instead (fix 19 Nov audit: one false injection flag
        # used to block every outgoing call for the rest of the session with no way out).
        return Decision("block", rule + "+injection",
                        reason + "; an untrusted page or result in this session contained instructions")
    if rule:
        rid = approvals.request_id(tool_key, args)
        st = approvals.status(rid)
        if st == "denied":
            return Decision("block", "approval.denied",
                            f"an administrator denied request {rid}", rid)
        if approvals.granted(rid, tool_key, rule, session.sid):
            return Decision("allow", "approval.granted", f"approved request {rid}", rid)
        return Decision("approval_requested", rule, reason, rid)

    return Decision("allow")


def block_message(d: Decision) -> str:
    """Text returned to the model. It tells the model to stop rather than work around the block."""
    head = f"ToolWarden blocked this call ({d.rule}): {d.reason}."
    if d.action == "approval_requested":
        return (f"{head} Approval request {d.request_id} has been sent to the administrator. "
                "Do not retry with different wording or another tool. Tell the user the action "
                "is waiting for approval; once approved, the same call will be allowed.")
    return f"{head} Do not try to work around this. Tell the user what was blocked and why."
