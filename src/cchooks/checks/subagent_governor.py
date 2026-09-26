"""9. Subagent governor: cap concurrent and per-session subagents.

Parallel Agent calls fire their PreToolUse hooks before any SubagentStart,
so a slot is *reserved* atomically in PreToolUse (keyed by tool_use_id,
with a short TTL) and converted to a running agent at SubagentStart.
SubagentStop and a completed foreground PostToolUse release it. Subagents
run in the background by default, so SubagentStop is the main release
signal; a stale timeout covers crashes.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from .. import state
from ..engine import Context

NAME = "subagent_governor"
KIND = "usability"
AGENT_TOOLS = ("Agent", "Task")


def _store(ctx: Context) -> state.Store:
    return state.Store(ctx.session, "governor")


def _prune(d: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    now = time.time()
    ttl = float(cfg.get("pending_ttl_seconds", 180))
    stale = float(cfg.get("stale_minutes", 90)) * 60
    d["pending"] = {k: v for k, v in d.get("pending", {}).items() if now - v["ts"] < ttl}
    d["running"] = {k: v for k, v in d.get("running", {}).items() if now - v["ts"] < stale}


def _describe(d: Dict[str, Any]) -> str:
    items = [v.get("type", "?") for v in d["running"].values()] + \
            ["%s (starting)" % v.get("type", "?") for v in d["pending"].values()]
    return ", ".join(items) or "none"


def pre_tool(ctx: Context):
    if ctx.tool not in AGENT_TOOLS:
        return None
    cfg = ctx.ccfg
    max_c, max_total = int(cfg.get("max_concurrent", 4)), int(cfg.get("max_per_session", 30))
    agent_type = ctx.tool_input.get("subagent_type") or "general-purpose"
    with _store(ctx).update() as d:
        _prune(d, cfg)
        active = len(d["running"]) + len(d["pending"])
        total = int(d.get("total", 0)) + len(d["pending"])
        if active >= max_c:
            return ctx.finding(
                "deny",
                reason="Subagent limit: %d of %d concurrent subagents are already running (%s). Wait for one "
                       "to finish, do this step yourself, or batch the work into fewer subagents."
                       % (active, max_c, _describe(d)),
                user_msg="Denied a %s subagent: %d/%d already running." % (agent_type, active, max_c),
                audit_detail="concurrent cap %d/%d" % (active, max_c))
        if total >= max_total:
            return ctx.finding(
                "deny",
                reason="Subagent budget: this session has already started %d subagents (limit %d). Continue "
                       "the work directly, or ask the user to raise subagent_governor.max_per_session."
                       % (total, max_total),
                audit_detail="session cap %d/%d" % (total, max_total))
        d["pending"][ctx.event.get("tool_use_id") or "t%f" % time.time()] = {"ts": time.time(), "type": agent_type}
    return None


def on_start(ctx: Context):
    agent_id = ctx.event.get("agent_id")
    agent_type = ctx.event.get("agent_type") or "general-purpose"
    if not agent_id:
        return None
    with _store(ctx).update() as d:
        _prune(d, ctx.ccfg)
        if agent_id in d["running"]:
            d["running"][agent_id]["ts"] = time.time()  # resumed
            return None
        # bind to the oldest reservation of this type, else the oldest of any type
        pend = sorted(d["pending"].items(), key=lambda kv: kv[1]["ts"])
        match = next((k for k, v in pend if v.get("type") == agent_type), None) or (pend[0][0] if pend else None)
        if match:
            d["pending"].pop(match)
        d["total"] = int(d.get("total", 0)) + 1
        d["running"][agent_id] = {"ts": time.time(), "type": agent_type, "tool_use_id": match}
    return None


def release_reservation(session: str, tool_use_id: str) -> None:
    """Called by the engine when another check denied the Agent call this check reserved for."""
    store = state.Store(session, "governor")
    with store.update() as d:
        d.get("pending", {}).pop(tool_use_id, None)


def _release(ctx: Context, agent_id: str = "", tool_use_id: str = "") -> None:
    with _store(ctx).update() as d:
        _prune(d, ctx.ccfg)
        if tool_use_id:
            d["pending"].pop(tool_use_id, None)
        for k in list(d["running"]):
            v = d["running"][k]
            if (agent_id and (k == agent_id or k.endswith(agent_id) or agent_id.endswith(k))) or \
                    (tool_use_id and v.get("tool_use_id") == tool_use_id):
                d["running"].pop(k)


def on_stop(ctx: Context):
    if ctx.event.get("agent_id") and ctx.event.get("agent_type") is not None:
        _release(ctx, agent_id=ctx.event["agent_id"])
    return None


def post_tool(ctx: Context):
    if ctx.tool not in AGENT_TOOLS:
        return None
    resp = ctx.event.get("tool_response") or {}
    if isinstance(resp, dict) and resp.get("status") == "async_launched":
        return None  # still running; SubagentStop releases it
    _release(ctx, agent_id=str(resp.get("agentId", "")) if isinstance(resp, dict) else "",
             tool_use_id=ctx.event.get("tool_use_id", ""))
    return None


def post_failure(ctx: Context):
    if ctx.tool in AGENT_TOOLS:
        _release(ctx, tool_use_id=ctx.event.get("tool_use_id", ""))
    return None


HANDLERS = {
    "PreToolUse": pre_tool,
    "SubagentStart": on_start,
    "SubagentStop": on_stop,
    "PostToolUse": post_tool,
    "PostToolUseFailure": post_failure,
}
