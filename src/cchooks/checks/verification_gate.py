"""11. Verification gate: don't finish a turn on unverified code edits.

Tracks code-file edits and test/lint/typecheck/build runs. If Claude
tries to stop after editing code without running any of them, it gets one
nudge (via Stop additionalContext, which continues the turn) naming the
command this project most likely uses. It nudges once per batch of edits
and respects stop_hook_active, so it can't loop.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import List, Optional

from .. import state, util
from ..engine import Context

NAME = "verification_gate"
KIND = "usability"

DEFAULT_VERIFY = [
    r"\b(?:py\.?test|pytest|tox|nox|unittest|mypy|pyright|ruff|flake8|pylint|black\s+--check)\b",
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|lint|typecheck|type-check|check|build|tsc|verify|ci)\b",
    r"\b(?:npx\s+)?(?:tsc|jest|vitest|mocha|eslint|biome|playwright\s+test|cypress\s+run)\b",
    r"\bcargo\s+(?:test|check|clippy|build|nextest)\b", r"\bgo\s+(?:test|vet|build)\b", r"\bgolangci-lint\b",
    r"\b(?:make|just|task)\s+(?:test|check|lint|build|verify|ci)\b",
    r"\b(?:mvn|mvnw|gradle|gradlew)\b[^|;&]*\b(?:test|verify|check|build)\b",
    r"\bdotnet\s+(?:test|build)\b", r"\b(?:rspec|rubocop|rake\s+test|bundle\s+exec\s+(?:rspec|rake))\b",
    r"\b(?:phpunit|phpstan|composer\s+test)\b", r"\bswift\s+(?:test|build)\b", r"\bInvoke-Pester\b",
    r"\bshellcheck\b", r"\bpython[\d.]*\s+-m\s+(?:pytest|unittest|mypy)\b", r"\buv\s+run\s+(?:pytest|mypy|ruff)\b",
]


def _store(ctx: Context) -> state.Store:
    return state.Store(ctx.session, "verify")


def _is_code(path: str, exts: List[str]) -> bool:
    return os.path.splitext(path)[1].lower() in exts


def suggest_command(project: str) -> Optional[str]:
    def exists(*names: str) -> bool:
        return any(os.path.exists(os.path.join(project, n)) for n in names)

    try:
        with open(os.path.join(project, "package.json"), "r", encoding="utf-8") as f:
            scripts = json.load(f).get("scripts", {})
        for s in ("test", "typecheck", "lint", "build"):
            if s in scripts:
                return "npm run %s" % s if s != "test" else "npm test"
    except (OSError, ValueError, AttributeError):
        pass
    if exists("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini"):
        return "pytest" if exists("tests", "test") else "python -m pytest"
    if exists("Cargo.toml"):
        return "cargo test"
    if exists("go.mod"):
        return "go test ./..."
    if exists("pom.xml"):
        return "mvn test"
    if exists("build.gradle", "build.gradle.kts"):
        return "gradle test"
    if exists("Makefile"):
        return "make test"
    return None


def post_tool(ctx: Context, failed: bool = False):
    cfg = ctx.ccfg
    ti = ctx.tool_input
    if ctx.tool in ("Edit", "Write", "MultiEdit", "NotebookEdit") and not failed:
        path = util.norm_path(ti.get("file_path") or ti.get("notebook_path") or "", ctx.cwd)
        if path and _is_code(path, cfg.get("code_extensions", [])):
            with _store(ctx).update() as d:
                d["last_edit"] = time.time()
                files = d.setdefault("edited", [])
                if path not in files:
                    files.append(path)
                del files[:-50]
    elif ctx.is_shell:
        patterns = cfg.get("commands") or DEFAULT_VERIFY
        if any(re.search(p, ctx.command, re.IGNORECASE) for p in patterns):
            with _store(ctx).update() as d:
                d["last_verify"] = time.time()
                d["last_verify_ok"] = not failed
                d["edited"] = []
    return None


def post_failure(ctx: Context):
    return post_tool(ctx, failed=True)


def on_stop(ctx: Context):
    if ctx.event.get("stop_hook_active"):
        return None
    with _store(ctx).update() as d:
        last_edit, last_verify = d.get("last_edit", 0), d.get("last_verify", 0)
        if not last_edit or last_verify >= last_edit or d.get("nudged_for", 0) >= last_edit:
            return None
        d["nudged_for"] = last_edit
        files = [os.path.basename(p) for p in d.get("edited", [])]
    cmd = suggest_command(ctx.project)
    how = "Run `%s`" % cmd if cmd else "Run the project's tests, linter or type checker"
    text = ("Code files were edited this turn (%s) and no test, lint, typecheck or build command has run since. "
            "%s and report the result. If verification genuinely doesn't apply here, say so in one sentence "
            "and stop." % (", ".join(files[:6]) + (" …" if len(files) > 6 else ""), how))
    if ctx.mode == "enforce":
        return ctx.finding("context", context=text, audit_detail="nudged: %d files" % len(files))
    return ctx.finding("warn", user_msg="Edited %d code file(s) without running tests/lint since. %s."
                                        % (len(files), how))


HANDLERS = {"PostToolUse": post_tool, "PostToolUseFailure": post_failure, "Stop": on_stop}
