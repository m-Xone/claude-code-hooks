"""8. Tool-cost ledger: where did this session's tokens go?

Two kinds of number, labelled as such in the report:
  * exact  - API usage (input/output/cache) read from the main and subagent
             transcripts, per model and per subagent type
  * est.   - per-tool context cost: the size of each tool's results (what it
             adds to context and is re-read on every later turn), plus the
             output tokens spent writing each tool's calls
Per-tool latency comes from the duration_ms Claude Code reports.

See it with `cli.py report`, or live in the status line (`cli.py statusline`).
"""

from __future__ import annotations

from typing import Any, Dict

from .. import state, transcript, util
from ..engine import Context

NAME = "cost_ledger"
KIND = "usability"


def store(session: str) -> state.Store:
    return state.Store(session, "ledger")


def _tool_bucket(d: Dict[str, Any], agent: str, tool: str) -> Dict[str, Any]:
    scope = d.setdefault("tools", {}).setdefault(agent or "main", {})
    return scope.setdefault(tool, {"calls": 0, "fails": 0, "result_chars": 0, "input_chars": 0, "ms": 0})


def _record(ctx: Context, failed: bool) -> None:
    tool = ctx.tool or "?"
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        tool = "mcp:%s" % parts[1] if len(parts) > 2 else tool
    resp = ctx.event.get("error") if failed else ctx.event.get("tool_response")
    with store(ctx.session).update() as d:
        b = _tool_bucket(d, ctx.event.get("agent_type") if ctx.event.get("agent_id") else "", tool)
        b["calls"] += 1
        b["fails"] += 1 if failed else 0
        b["result_chars"] += util.json_size(resp) if resp is not None else 0
        b["input_chars"] += util.json_size(ctx.tool_input)
        b["ms"] += int(ctx.event.get("duration_ms") or 0)
        d.setdefault("meta", {}).update(cwd=ctx.cwd, transcript=ctx.event.get("transcript_path"))


def post_tool(ctx: Context):
    _record(ctx, failed=False)


def post_failure(ctx: Context):
    _record(ctx, failed=True)


def _ingest(d: Dict[str, Any], path: str, scope_key: str) -> None:
    offsets = d.setdefault("offsets", {})
    usage, new_off = transcript.read_usage(path, int(offsets.get(path, 0)))
    offsets[path] = new_off
    scope = d.setdefault("usage", {}).setdefault(scope_key, {"by_model": {}, "tool_calls": {}, "messages": 0})
    for model, u in usage["by_model"].items():
        transcript.add_usage(scope["by_model"].setdefault(model, transcript.empty_usage()), u)
    for name, t in usage["tool_calls"].items():
        cur = scope["tool_calls"].setdefault(name, {"calls": 0, "gen_tokens": 0})
        cur["calls"] += t["calls"]
        cur["gen_tokens"] += t["gen_tokens"]
    scope["messages"] += usage["messages"]


def on_stop(ctx: Context):
    path = ctx.event.get("transcript_path")
    if path:
        with store(ctx.session).update() as d:
            _ingest(d, path, "main")


def on_subagent_stop(ctx: Context):
    path = ctx.event.get("agent_transcript_path")
    agent_type = ctx.event.get("agent_type")
    if not path or not agent_type:  # internal agents (prompt suggestions etc.) have no type
        return None
    with store(ctx.session).update() as d:
        _ingest(d, path, "agent:" + agent_type)
        runs = d.setdefault("agent_runs", {})
        runs[agent_type] = runs.get(agent_type, 0) + (0 if ctx.event.get("stop_hook_active") else 1)
    return None


HANDLERS = {
    "PostToolUse": post_tool,
    "PostToolUseFailure": post_failure,
    "Stop": on_stop,
    "SubagentStop": on_subagent_stop,
}
