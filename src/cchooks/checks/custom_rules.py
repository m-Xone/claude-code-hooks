"""13. Custom rules: your own checks, written as small JSON files (see rules.py).

Each rule has its own mode, and new rules start in warn. The check's own
mode caps every rule: set custom_rules to "warn" and nothing is enforced.
"""

from __future__ import annotations

import copy
import traceback

from .. import rules as rules_mod
from .. import state
from ..engine import Context, Finding, _apply_mode, _crash_finding

NAME = "custom_rules"
KIND = "security"

BLOCKING_ACTIONS = ("block", "deny", "ask", "redact")


def _load(ctx: Context):
    key = "rules"
    if key not in ctx._cache:
        ctx._cache[key] = rules_mod.load_all(ctx.project, include_project=ctx.ccfg.get("project_rules", True))
    return ctx._cache[key]


def _finding(ctx: Context, rule: rules_mod.Rule):
    ev, msg, label = ctx.name, rule.message, rule.label
    tool = ctx.tool or ev
    audit = "%s matched on %s" % (rule.id, tool)
    if rule.action == "block" and ev == "UserPromptSubmit":
        marker = ctx.cfg["checks"].get("prompt_gate", {}).get("override_marker") or "[[allow-sensitive]]"
        if rule.override and marker in (ctx.event.get("prompt") or ""):
            return Finding(label, "warn", user_msg="Sent with the override marker despite: " + msg,
                           audit_detail="override used: " + audit)
        how = " Edit it and resend%s." % (", or add %s to send it anyway" % marker if rule.override else "")
        return Finding(label, "block", reason="Your prompt was NOT sent: %s%s" % (msg, how), audit_detail=audit)
    if rule.action == "redact":
        resp = ctx.event.get("tool_response")
        new, n = rules_mod.redact(rule, resp)
        if not n:
            return None
        return Finding(label, "redact", updated_output=new,
                       reason="%d value(s) were redacted from this %s result by the user's rule '%s': %s"
                              % (n, tool, rule.id, msg),
                       user_msg="Redacted %d value(s) from %s output: %s" % (n, tool, msg),
                       audit_detail="%s (%d redacted)" % (audit, n))
    if rule.action == "block":  # Stop / SubagentStop: Claude keeps working with this as feedback
        return Finding(label, "block", reason=msg, user_msg=msg, audit_detail=audit)
    if rule.action in ("deny", "ask"):
        return Finding(label, rule.action, reason=msg, audit_detail=audit)
    if rule.action == "warn":
        return Finding(label, "warn", user_msg=msg, audit_detail=audit)
    return Finding(label, "context", context=msg, audit_detail=audit)


def evaluate(ctx: Context):
    if ctx.name in ("Stop", "SubagentStop") and ctx.event.get("stop_hook_active"):
        return None  # already continuing because of a Stop hook: don't loop
    rules, _problems = _load(ctx)
    out = []
    for rule in rules:
        if rule.mode == "off" or not rules_mod.applies(rule, ctx.event):
            continue
        enforced = rule.mode == "enforce" and ctx.mode == "enforce"
        try:
            if not rules_mod.matches(rule, ctx.event):
                continue
            f = _finding(ctx, rule)
        except Exception as e:  # noqa: BLE001 - one broken rule must not take the others down
            state.audit(ctx.event, rule.label, "crash", traceback.format_exc(limit=3)[-800:])
            if enforced and rule.action in BLOCKING_ACTIONS:
                sub = copy.copy(ctx)
                sub.check = rule.label
                out.append(_crash_finding(sub, KIND, "%s: %s" % (type(e).__name__, e)))
            else:
                out.append(Finding(rule.label, "warn", user_msg="rule failed (%s) and was skipped" % e))
            continue
        if f is None:
            continue
        f = _apply_mode(f, "enforce" if enforced else "warn", ctx.name)
        if f.action == "redact":
            ctx.event["tool_response"] = f.updated_output  # later rules see the redacted text
        out.append(f)
    return out


def on_session_start(ctx: Context):
    rules, problems = _load(ctx)
    if not problems:
        return None
    shown = problems[:5] + (["+%d more" % (len(problems) - 5)] if len(problems) > 5 else [])
    return Finding(NAME, "warn", user_msg="%d custom rule file(s) ignored:\n  - %s\nRun `cli.py rules` for "
                   "details." % (len(problems), "\n  - ".join(shown)),
                   audit_detail="invalid rules: " + "; ".join(problems)[:600])


HANDLERS = {
    "SessionStart": on_session_start,
    "UserPromptSubmit": evaluate,
    "PreToolUse": evaluate,
    "PostToolUse": evaluate,
    "Stop": evaluate,
    "SubagentStop": evaluate,
}
