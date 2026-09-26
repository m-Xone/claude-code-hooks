"""10. Slop detector: flag AI-sounding prose.

  * Chat replies (Stop): scored and reported to you as a one-line status
    message. Never forces a rewrite: you've already read the reply, and
    continuing the turn to redo it only costs tokens.
  * Prose written to disk (Write/Edit on .md/.txt/README..., `git commit -m`,
    `gh pr create --body`): in enforce mode the write is denied with the
    specific tells, so Claude rewrites before it lands. Warn mode reports.
"""

from __future__ import annotations

import re

from .. import util
from ..detectors import slop
from ..engine import Context

NAME = "slop_detector"
KIND = "usability"

PR_OR_COMMIT = re.compile(
    r"\bgit\s+commit\b[^|;&]*?(?:-m|--message)[= ]\s*(['\"])(?P<a>.*?)\1|"
    r"\bgh\s+(?:pr|issue)\s+(?:create|comment|edit)\b[^|;&]*?(?:--body|-b)[= ]\s*(['\"])(?P<b>.*?)\3",
    re.DOTALL)


def _prose_from_tool(ctx: Context):
    ti = ctx.tool_input
    if ctx.tool in ("Write", "Edit", "MultiEdit"):
        path = util.norm_path(ti.get("file_path") or "", ctx.cwd)
        if not util.path_matches(path, ctx.ccfg.get("prose_globs", [])):
            return None, None
        text = ti.get("content") or ti.get("new_string") or "\n".join(
            e.get("new_string", "") for e in ti.get("edits") or [] if isinstance(e, dict))
        return text, ti.get("file_path")
    if ctx.is_shell:
        m = PR_OR_COMMIT.search(ctx.command)
        if m:
            return (m.group("a") or m.group("b") or ""), "commit/PR text"
    return None, None


def pre_tool(ctx: Context):
    text, where = _prose_from_tool(ctx)
    if not text:
        return None
    rep = slop.score(text, ctx.ccfg.get("extra_phrases", []))
    if rep.score < float(ctx.ccfg.get("file_threshold", 5)):
        return None
    return ctx.finding(
        "deny",
        reason="The prose for %s reads as AI-generated (score %.1f: %s). Rewrite it plainly: state facts "
               "directly, drop the flagged phrasing and structures, then write it again."
               % (where, rep.score, rep.summary()),
        audit_detail="file score %.1f: %s" % (rep.score, rep.summary()))


def on_stop(ctx: Context):
    if ctx.event.get("stop_hook_active"):
        return None
    msg = ctx.event.get("last_assistant_message") or ""
    rep = slop.score(msg, ctx.ccfg.get("extra_phrases", []))
    if rep.score < float(ctx.ccfg.get("chat_threshold", 6)):
        return None
    return ctx.finding("warn", user_msg="slop score %.1f (%d words): %s" % (rep.score, rep.words, rep.summary()),
                       audit_detail="chat score %.1f" % rep.score)


HANDLERS = {"PreToolUse": pre_tool, "Stop": on_stop}
