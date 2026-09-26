"""Incremental token-usage extraction from Claude Code transcript JSONL.

Hooks never receive token counts, but every assistant message in the
transcript carries `message.usage`. A message split into several content
blocks appears on several lines with the same message id, so usage is
de-duplicated by id (last line wins).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple

USAGE_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def empty_usage() -> Dict[str, int]:
    return {k: 0 for k in USAGE_KEYS}


def read_usage(path: str, offset: int = 0) -> Tuple[Dict[str, Any], int]:
    """Parse from byte `offset`. Returns ({by_model, tool_calls, messages}, new_offset).

    Only complete lines are consumed, so a line being written concurrently
    is picked up on the next call.
    """
    result: Dict[str, Any] = {"by_model": {}, "tool_calls": {}, "messages": 0}
    if not path:
        return result, offset
    path = os.path.expanduser(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        return result, offset
    if size < offset:  # rewritten (e.g. compaction) - start over
        offset = 0
    latest: Dict[str, Tuple[str, Dict[str, int], Dict[str, int]]] = {}
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read()
    end = data.rfind(b"\n")
    if end < 0:
        return result, offset
    for raw in data[: end + 1].splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("type") != "assistant":
            continue
        msg = rec.get("message") or {}
        usage = msg.get("usage")
        if not isinstance(usage, dict):
            continue
        mid = msg.get("id") or rec.get("uuid") or str(len(latest))
        tools: Dict[str, int] = {}
        for block in msg.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name", "?")
                tools[name] = tools.get(name, 0) + 1
        prev = latest.get(mid)
        if prev:  # merge tool blocks seen on earlier lines of the same message
            for k, v in prev[2].items():
                tools[k] = tools.get(k, 0) + v
        latest[mid] = (msg.get("model") or "unknown",
                       {k: int(usage.get(k) or 0) for k in USAGE_KEYS}, tools)
    for model, usage, tools in latest.values():
        bucket = result["by_model"].setdefault(model, empty_usage())
        for k, v in usage.items():
            bucket[k] += v
        # output tokens of a message that made tool calls are the cost of *writing* those calls
        n = sum(tools.values())
        for name, c in tools.items():
            t = result["tool_calls"].setdefault(name, {"calls": 0, "gen_tokens": 0})
            t["calls"] += c
            t["gen_tokens"] += int(usage["output_tokens"] * c / n) if n else 0
    result["messages"] = len(latest)
    return result, offset + end + 1


def add_usage(into: Dict[str, int], more: Dict[str, int]) -> None:
    for k in USAGE_KEYS:
        into[k] = into.get(k, 0) + int(more.get(k, 0))
