"""1. Prompt gate: stop secrets and sensitive PII before they reach the model.

UserPromptSubmit can block a prompt but cannot ask for confirmation, and a
blocked prompt is erased from context, so "confirm" means: block, tell the
user what was found (redacted), and let them resubmit with an override
marker if they really meant to send it.
"""

from __future__ import annotations

from ..detectors import secrets
from ..engine import Context

NAME = "prompt_gate"
KIND = "security"


def _strip_pasted_markers(text: str) -> str:
    import re
    return re.sub(r"</?pasted_content[^>]*>", " ", text)


def on_prompt(ctx: Context):
    prompt = ctx.event.get("prompt") or ""
    if not isinstance(prompt, str) or not prompt.strip():
        return None
    cfg = ctx.ccfg
    marker = cfg.get("override_marker") or "[[allow-sensitive]]"
    matches = secrets.scan(_strip_pasted_markers(prompt), secrets=True, pii=True)
    if not matches:
        return None
    block = [m for m in matches if m.severity in cfg.get("block_severities", [])]
    warn = [m for m in matches if m.severity in cfg.get("warn_severities", []) and m not in block]
    summary_all = secrets.summarize(matches)

    if block and marker in prompt:
        return ctx.finding("warn",
                           user_msg="Sent with override marker despite: %s" % secrets.summarize(block),
                           audit_detail="override used: " + summary_all)
    if block:
        reason = (
            "Your prompt was NOT sent. It appears to contain: %s.\n"
            "  - If this was a mistake, remove the value (use an env var or a file path instead) and resend.\n"
            "  - If you really intend to send it to the model, resend it with %s anywhere in the text."
            % (secrets.summarize(block), marker)
        )
        return ctx.finding("block", reason=reason, audit_detail="blocked: " + summary_all)
    if warn:
        return ctx.finding(
            "warn",
            user_msg="Prompt contains personal data: %s. It was sent; avoid pasting real personal data "
                     "where test values would do." % secrets.summarize(warn),
            context="The user's prompt contains personal data (%s). Do not copy it into files, commits, "
                    "logs or external requests unless the user asks you to." % ", ".join(sorted({m.kind for m in warn})),
            audit_detail="warned: " + summary_all,
        )
    return None


HANDLERS = {"UserPromptSubmit": on_prompt}
