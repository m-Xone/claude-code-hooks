"""12. Loop detector: notice when the agent is spinning.

  * the same call repeated N times in a short window     -> nudge
  * the same call failing repeatedly                     -> deny the next identical retry
  * the same file re-read N times without an edit        -> nudge (wasted context)
  * a streak of failing shell commands                   -> nudge to step back
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List

from .. import state, util
from ..engine import Context

NAME = "loop_detector"
KIND = "usability"
IGNORE_TOOLS = {"TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "AskUserQuestion", "ToolSearch",
                "Monitor", "ScheduleWakeup"}


def signature(tool: str, tool_input: Dict[str, Any]) -> str:
    ti = {k: v for k, v in tool_input.items() if k not in ("description", "timeout")}
    raw = tool + json.dumps(ti, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _store(ctx: Context) -> state.Store:
    return state.Store(ctx.session, "loops")


def pre_tool(ctx: Context):
    if ctx.tool in IGNORE_TOOLS:
        return None
    d = _store(ctx).read()
    sig = signature(ctx.tool, ctx.tool_input)
    window = float(ctx.ccfg.get("failure_window_minutes", 10)) * 60
    entry = d.get("fail_counts", {}).get(sig)
    fails, last = (entry if isinstance(entry, list) else [0, 0])
    limit = int(ctx.ccfg.get("failure_threshold", 3))
    if fails >= limit and time.time() - last < window:
        return ctx.finding(
            ctx.ccfg.get("failure_action", "ask"),
            reason="This exact %s call has failed %d times in a row with the same input. Retrying it "
                   "unchanged probably won't help: read the last error and change the approach, unless you're "
                   "deliberately waiting on something (a server starting, say)." % (ctx.tool, fails),
            audit_detail="identical failing call x%d" % fails)
    return None


def _record(ctx: Context, failed: bool) -> List[str]:
    cfg = ctx.ccfg
    window = int(cfg.get("window", 12))
    sig = signature(ctx.tool, ctx.tool_input)
    nudges: List[str] = []
    with _store(ctx).update() as d:
        hist = d.setdefault("history", [])
        hist.append({"sig": sig, "tool": ctx.tool, "failed": failed, "ts": time.time()})
        del hist[:-window]
        fc = d.setdefault("fail_counts", {})
        if not failed and ctx.tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
            fc.clear()  # something changed; re-running a failed test is legitimate now
        elif failed:
            prev = fc.get(sig) if isinstance(fc.get(sig), list) else [0, 0]
            fc[sig] = [prev[0] + 1, time.time()]
        else:
            fc.pop(sig, None)
        if len(fc) > 200:
            d["fail_counts"] = dict(list(fc.items())[-100:])

        repeats = sum(1 for h in hist if h["sig"] == sig)
        if repeats >= int(cfg.get("repeat_threshold", 3)) and d.get("last_nudge_sig") != sig:
            nudges.append("You have made this same %s call %d times in the last %d tool calls. If the result "
                          "isn't changing, try a different approach." % (ctx.tool, repeats, len(hist)))
            d["last_nudge_sig"] = sig

        # re-reads without intervening edits
        reads = d.setdefault("reads", {})
        path = util.norm_path(ctx.tool_input.get("file_path") or "", ctx.cwd) if ctx.tool_input.get("file_path") else ""
        if ctx.tool in ("Edit", "Write", "MultiEdit", "NotebookEdit") and path:
            reads.pop(path, None)
        elif ctx.tool == "Read" and path and not failed:
            reads[path] = reads.get(path, 0) + 1
            if reads[path] == int(cfg.get("reread_threshold", 4)):
                nudges.append("%s has now been read %d times without being edited. Its content is already in "
                              "context; re-reading adds tokens without new information." % (path, reads[path]))
            if len(reads) > 300:
                d["reads"] = dict(list(reads.items())[-150:])

        streak = 0
        for h in reversed(hist):
            if h["tool"] in ("Bash", "PowerShell") and h["failed"]:
                streak += 1
            elif h["tool"] in ("Bash", "PowerShell"):
                break
        if failed and ctx.is_shell and streak == 5:
            nudges.append("The last 5 shell commands all failed. Stop and diagnose the common cause (wrong "
                          "directory, missing dependency, wrong shell syntax for this OS) before running more.")
    return nudges


def post_tool(ctx: Context):
    if ctx.tool in IGNORE_TOOLS:
        return None
    nudges = _record(ctx, failed=False)
    return ctx.finding("context", context=" ".join(nudges), audit_detail="nudge") if nudges else None


def post_failure(ctx: Context):
    if ctx.tool in IGNORE_TOOLS or ctx.event.get("is_interrupt"):
        return None
    nudges = _record(ctx, failed=True)
    return ctx.finding("context", context=" ".join(nudges), audit_detail="nudge") if nudges else None


HANDLERS = {"PreToolUse": pre_tool, "PostToolUse": post_tool, "PostToolUseFailure": post_failure}
