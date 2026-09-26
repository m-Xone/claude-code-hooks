"""6. Secret-leak prevention, in three places:

  * tool results: secrets in anything a tool returns (a `cat`, an MCP
    response, a log file) are replaced with [REDACTED:kind] before Claude
    sees them, via PostToolUse updatedToolOutput. The shape of the result is
    preserved so Claude Code accepts the replacement.
  * file writes: Write/Edit content containing a secret needs confirmation.
  * commits: `git commit` is denied when the staged diff adds a secret.
"""

from __future__ import annotations

import re
import subprocess
from typing import List

from .. import util
from ..detectors import secrets
from ..engine import Context

NAME = "secret_leaks"
KIND = "security"

WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
GIT_COMMIT = re.compile(r"\bgit\b(?:\s+-[Cc]\s+\S+)*[^|;&]*\bcommit\b")


def _written_text(ti: dict) -> str:
    parts: List[str] = []
    for k in ("content", "new_string", "new_source"):
        if isinstance(ti.get(k), str):
            parts.append(ti[k])
    for e in ti.get("edits") or []:
        if isinstance(e, dict) and isinstance(e.get("new_string"), str):
            parts.append(e["new_string"])
    return "\n".join(parts)


def _staged_added_lines(cwd: str, include_unstaged: bool) -> str:
    def diff(args: List[str]) -> str:
        try:
            r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True,
                               timeout=8, encoding="utf-8", errors="replace")
            return r.stdout if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    out = diff(["diff", "--cached", "--no-color", "-U0"])
    if include_unstaged:
        out += diff(["diff", "--no-color", "-U0"])
    added, current = [], ""
    for line in out.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+") and not line.startswith("+++"):
            added.append("%s: %s" % (current, line[1:]))
    return "\n".join(added)


def pre_tool(ctx: Context):
    cfg = ctx.ccfg
    ti = ctx.tool_input
    if ctx.tool in WRITE_TOOLS:
        path = util.norm_path(ti.get("file_path") or ti.get("notebook_path") or "", ctx.cwd)
        if util.path_matches(path, cfg.get("ignore_paths", [])):
            return None
        found = secrets.scan(_written_text(ti))
        if not found:
            return None
        return ctx.finding(
            cfg.get("write_action", "ask"),
            reason="Claude is writing what looks like a secret into %s: %s. Prefer an environment variable "
                   "or secret manager reference." % (ti.get("file_path"), secrets.summarize(found)),
            audit_detail="%s %s" % (path, secrets.summarize(found)),
        )

    if ctx.is_shell and cfg.get("scan_commits", True) and GIT_COMMIT.search(ctx.command):
        include_unstaged = bool(re.search(r"\bcommit\b[^|;&]*(?:\s-[a-zA-Z]*a|\s--all\b)", ctx.command))
        found = secrets.scan(_staged_added_lines(ctx.cwd, include_unstaged))
        found = [m for m in found if m.severity in ("critical", "high", "medium")]
        if found:
            return ctx.finding(
                "deny",
                reason="The staged changes add what look like secrets: %s. Remove them (and rotate them if they "
                       "were real), move them to environment variables, then commit again. If these are known "
                       "test fixtures, tell the user so they can commit manually." % secrets.summarize(found),
                audit_detail="commit blocked: " + secrets.summarize(found),
            )
    return None


def post_tool(ctx: Context):
    cfg = ctx.ccfg
    if not cfg.get("redact_tool_output", True) or ctx.tool in WRITE_TOOLS:
        return None
    resp = ctx.event.get("tool_response")
    if resp is None:
        return None
    severities = set(cfg.get("redact_severities", ["critical", "high"]))
    kinds: List[str] = []

    def scrub(s: str) -> str:
        if len(s) < 16:
            return s
        found = [m for m in secrets.scan(s) if m.severity in severities]
        if not found:
            return s
        kinds.extend(m.kind for m in found)
        return secrets.redact_text(s, found)

    new = util.map_strings(resp, scrub)
    if not kinds:
        return None
    uniq = sorted(set(kinds))
    return ctx.finding(
        "redact",
        updated_output=new,
        reason="%d secret value(s) (%s) were redacted from this %s result before you saw it. Refer to them by "
               "name or location rather than asking for the value." % (len(kinds), ", ".join(uniq), ctx.tool),
        user_msg="Redacted %d secret(s) (%s) from %s output." % (len(kinds), ", ".join(uniq), ctx.tool),
        audit_detail="redacted %s from %s" % (",".join(uniq), ctx.tool),
    )


HANDLERS = {"PreToolUse": pre_tool, "PostToolUse": post_tool}
