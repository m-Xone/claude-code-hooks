"""Event dispatcher: runs every enabled check for an event, merges their
findings into the single JSON object Claude Code expects, and decides the
exit code.

Mode semantics per check:
  off      the check does not run
  warn     blocking outcomes (deny/ask/block/redact) become a visible warning
  enforce  outcomes apply as written
"""

from __future__ import annotations

import os
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import config as config_mod
from . import state, util

BLOCKING = ("deny", "ask", "block", "redact")


@dataclass
class Finding:
    check: str = ""
    action: str = "context"   # deny | ask | block | redact | warn | context
    reason: str = ""          # deny/block: shown to Claude. ask: shown to the user
    context: str = ""         # additionalContext for Claude
    user_msg: str = ""        # systemMessage shown to the user
    updated_output: Any = None
    audit_detail: str = ""    # redacted summary for the audit log; empty = don't log


@dataclass
class Context:
    event: Dict[str, Any]
    cfg: Dict[str, Any]
    check: str = ""
    mode: str = "enforce"
    _cache: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.event.get("hook_event_name", "")

    @property
    def session(self) -> str:
        return self.event.get("session_id") or "nosession"

    @property
    def tool(self) -> str:
        return self.event.get("tool_name") or ""

    @property
    def tool_input(self) -> Dict[str, Any]:
        ti = self.event.get("tool_input")
        return ti if isinstance(ti, dict) else {}

    @property
    def cwd(self) -> str:
        return util.norm_path(self.event.get("cwd") or os.getcwd())

    @property
    def project(self) -> str:
        return util.project_dir(self.event)

    @property
    def ccfg(self) -> Dict[str, Any]:
        return self.cfg["checks"].get(self.check, {})

    @property
    def is_shell(self) -> bool:
        return self.tool in ("Bash", "PowerShell")

    @property
    def command(self) -> str:
        c = self.tool_input.get("command")
        return c if isinstance(c, str) else ""

    def finding(self, action: str, **kw: Any) -> Finding:
        return Finding(check=self.check, action=action, **kw)


Handler = Callable[[Context], Optional[Any]]


def _registry() -> List[Tuple[str, str, Dict[str, Handler]]]:
    from .checks import ALL
    return [(m.NAME, m.KIND, m.HANDLERS) for m in ALL]


def _as_list(r: Any) -> List[Finding]:
    if r is None:
        return []
    return list(r) if isinstance(r, (list, tuple)) else [r]


def _crash_finding(ctx: Context, kind: str, err: str) -> Finding:
    msg = ("cchooks check '%s' failed internally (%s). " % (ctx.check, err))
    fail_closed = (kind == "security" and ctx.mode == "enforce" and ctx.cfg.get("fail_closed", True)
                   and not os.path.exists(state.fail_open_flag()))
    if not fail_closed:
        return Finding(ctx.check, "warn", user_msg=msg + "Continuing without it.")
    fix = ("Run `python -m cchooks doctor`, set this check's mode to \"warn\" in %s, "
           "or create %s to fail open." % (config_mod.user_config_path(), state.fail_open_flag()))
    if ctx.name == "PreToolUse":
        return Finding(ctx.check, "ask", reason=msg + "Asking instead of allowing silently. " + fix)
    if ctx.name == "UserPromptSubmit":
        return Finding(ctx.check, "block", reason=msg + "Prompt held back. " + fix)
    return Finding(ctx.check, "warn", user_msg=msg + fix)


def _apply_mode(f: Finding, mode: str, event_name: str) -> Finding:
    if mode == "enforce" or f.action not in BLOCKING:
        return f
    verb = {"deny": "denied", "ask": "asked about", "block": "blocked", "redact": "redacted"}[f.action]
    what = "this tool call" if event_name == "PreToolUse" else "this"
    note = "[warn mode] %s would have %s %s: %s" % (f.check, verb, what, f.reason or f.user_msg)
    return Finding(f.check, "warn", context=f.context, user_msg=util.truncate(note, 600),
                   audit_detail=f.audit_detail)


def run(event: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], int, str]:
    """Returns (json_output_or_None, exit_code, stderr_text)."""
    name = event.get("hook_event_name", "")
    t0 = time.perf_counter()
    try:
        cfg = config_mod.load(util.project_dir(event))
    except config_mod.ConfigError as e:
        cfg = config_mod.load("")  # fall back to defaults + nothing
        cfg["_config_error"] = str(e)

    findings: List[Finding] = []
    if cfg.get("_config_error"):
        findings.append(Finding("config", "warn", user_msg="cchooks: %s (using defaults)" % cfg["_config_error"]))

    for check, kind, handlers in _registry():
        fn = handlers.get(name)
        if fn is None:
            continue
        mode = config_mod.mode_of(cfg, check)
        if mode == "off":
            continue
        ctx = Context(event=event, cfg=cfg, check=check, mode=mode)
        try:
            results = _as_list(fn(ctx))
        except Exception as e:  # noqa: BLE001 - a hook must never crash Claude Code
            results = [_crash_finding(ctx, kind, "%s: %s" % (type(e).__name__, e))]
            state.audit(event, check, "crash", traceback.format_exc(limit=3)[-800:])
        for f in results:
            f.check = f.check or check
            f = _apply_mode(f, mode, name)
            if f.audit_detail:
                state.audit(event, f.check, f.action, f.audit_detail)
            if f.action == "redact" and f.updated_output is not None:
                event["tool_response"] = f.updated_output  # later checks redact on top of this one
            findings.append(f)

    if name == "SessionStart":
        try:
            n = state.prune_sessions(float(cfg.get("retention_days", 30) or 0), keep=event.get("session_id") or "")
            if n:
                state.audit(event, "housekeeping", "prune", "deleted %d session folder(s) older than %s days"
                            % (n, cfg.get("retention_days")))
        except (TypeError, ValueError):
            pass
    findings += _pending_notices(event)
    out, code, err = render(name, findings)
    if name == "PreToolUse" and event.get("tool_name") in ("Agent", "Task") and \
            ((out or {}).get("hookSpecificOutput") or {}).get("permissionDecision") == "deny":
        from .checks.subagent_governor import release_reservation
        release_reservation(event.get("session_id") or "nosession", event.get("tool_use_id") or "")
    if os.environ.get("CCHOOKS_TIMING"):
        err += "\n[cchooks] %s %.1fms" % (name, (time.perf_counter() - t0) * 1000)
    return out, code, err


# ------------------------------------------------------------------ notices

def queue_notice(session_id: str, text: str) -> None:
    """Deliver a message to the user on the next event that can show one.

    Used by ConfigChange, whose own output is never displayed.
    """
    with state.Store(session_id, "notices").update() as d:
        d.setdefault("items", []).append(text)


def _pending_notices(event: Dict[str, Any]) -> List[Finding]:
    if event.get("hook_event_name") not in ("UserPromptSubmit", "PreToolUse", "Stop"):
        return []
    store = state.Store(event.get("session_id") or "nosession", "notices")
    if not os.path.exists(store.path):
        return []
    with store.update() as d:
        items, d["items"] = d.get("items", []), []
    return [Finding("notice", "warn", user_msg=t) for t in items]


# ------------------------------------------------------------------- output

def _join(parts: List[str]) -> str:
    seen, out = set(), []
    for p in parts:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return "\n\n".join(out)


def render(name: str, findings: List[Finding]) -> Tuple[Optional[Dict[str, Any]], int, str]:
    by = lambda a: [f for f in findings if f.action == a]  # noqa: E731
    context = _join([f.context for f in findings])
    user_msg = _join(["[cchooks:%s] %s" % (f.check, f.user_msg) for f in findings if f.user_msg])
    out: Dict[str, Any] = {}
    hso: Dict[str, Any] = {"hookEventName": name}
    code, err = 0, ""

    if name == "PreToolUse":
        deny, ask = by("deny"), by("ask")
        if deny:
            reason = _join(["[cchooks:%s] %s" % (f.check, f.reason) for f in deny])
            hso.update(permissionDecision="deny", permissionDecisionReason=reason)
        elif ask:
            hso.update(permissionDecision="ask",
                       permissionDecisionReason=_join(["[cchooks:%s] %s" % (f.check, f.reason) for f in ask]))
        # never emit "allow": that would skip the user's own permission rules
    elif name in ("UserPromptSubmit", "Stop", "SubagentStop", "PostToolUse", "ConfigChange"):
        block = by("block")
        if block:
            out["decision"] = "block"
            out["reason"] = _join(["[cchooks:%s] %s" % (f.check, f.reason) for f in block])
            if name in ("UserPromptSubmit", "ConfigChange"):
                # exit 2 as well: if Claude Code ever rejected the JSON shape, the block still holds
                code, err = 2, _join([out["reason"], user_msg])
            if name == "UserPromptSubmit":
                hso["suppressOriginalPrompt"] = True
        if name == "PostToolUse":
            redact = by("redact")
            if redact:
                hso["updatedToolOutput"] = redact[-1].updated_output
                context = _join([context] + [f.reason for f in redact])

    if context and name not in ("ConfigChange",):
        hso["additionalContext"] = context[:9500]
    if user_msg:
        out["systemMessage"] = user_msg[:9500]
    if len(hso) > 1:
        out["hookSpecificOutput"] = hso
    return (out or None), code, err
