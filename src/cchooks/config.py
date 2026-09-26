"""Layered configuration.

Order (later wins): built-in DEFAULTS -> user config
(~/.claude/cchooks/config.json) -> project config (<project>/.claude/cchooks.json).

A project config comes from whatever repository you happen to open, so it is
treated as untrusted: it may only *tighten* security checks (raise a mode,
append extra patterns). Usability checks accept any project setting.
"""

from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict

from . import util

MODES = ("off", "warn", "enforce")

SECURITY_CHECKS = (
    "prompt_gate", "sensitive_paths", "destructive_commands", "injection_tripwire",
    "egress_guard", "secret_leaks", "tamper_guard",
)
USABILITY_CHECKS = (
    "cost_ledger", "subagent_governor", "slop_detector", "verification_gate", "loop_detector",
)
# Keys a project may extend on security checks (list append only).
# Regexes (extra_rules) are user-config only: a hostile repo could ship a catastrophic-backtracking
# pattern that times the hook out, and a timed-out hook allows the action.
PROJECT_APPENDABLE = {"extra_patterns", "protected_branches"}

DEFAULTS: Dict[str, Any] = {
    # On an internal error, security checks ask/block instead of silently allowing.
    "fail_closed": True,
    "checks": {
        "prompt_gate": {
            "mode": "enforce",
            "override_marker": "[[allow-sensitive]]",
            "block_severities": ["critical", "high"],
            "warn_severities": ["medium", "low"],
        },
        "sensitive_paths": {
            "mode": "enforce",
            "read_action": "deny",     # Read/Grep of a secret store
            "write_action": "ask",     # Edit/Write to one
            "shell_action": "ask",     # a Bash/PowerShell command naming one
            "extra_patterns": [],
            "allow_patterns": ["**/.env.example", "**/.env.sample", "**/.env.template",
                               "**/.env.dist", "~/.ssh/*.pub", "~/.ssh/known_hosts",
                               "~/.ssh/config"],
        },
        "destructive_commands": {
            "mode": "enforce",
            "protected_branches": ["main", "master", "production", "prod", "release", "trunk"],
            "extra_rules": [],  # [{"pattern": "...", "action": "ask|deny", "reason": "..."}]
        },
        "injection_tripwire": {
            "mode": "enforce",
            "scan_tools": ["WebFetch", "WebSearch", "mcp__*"],
            "scan_network_shell": True,          # Bash/PowerShell output of curl, wget, gh api, ...
            "scan_reads_outside_project": True,  # Read, or shell commands, touching files outside the project
            "min_score": 3,
        },
        "egress_guard": {
            "mode": "enforce",
            "allow_domains": [
                "localhost", "127.0.0.1", "::1",
                "github.com", "api.github.com", "raw.githubusercontent.com",
                "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
                "crates.io", "proxy.golang.org", "docs.python.org",
                "developer.mozilla.org", "code.claude.com", "docs.anthropic.com",
            ],
            "payload_min_len": 64,
        },
        "secret_leaks": {
            "mode": "enforce",
            "redact_tool_output": True,
            "redact_severities": ["critical", "high"],
            "scan_commits": True,
            "write_action": "ask",
            "ignore_paths": ["**/.env", "**/.env.*", "**/*.secrets.*"],
        },
        "tamper_guard": {
            "mode": "enforce",
            "extra_patterns": [],
        },
        "cost_ledger": {"mode": "enforce", "statusline_top_tools": 2},
        "subagent_governor": {
            "mode": "enforce",
            "max_concurrent": 4,
            "max_per_session": 30,
            "pending_ttl_seconds": 180,
            "stale_minutes": 90,
        },
        "slop_detector": {
            "mode": "warn",
            "chat_threshold": 6,       # score at which a chat reply is flagged to you
            "file_threshold": 5,       # score at which prose written to disk is flagged/blocked
            "prose_globs": ["**/*.md", "**/*.mdx", "**/*.rst", "**/*.txt", "**/README*",
                            "**/CHANGELOG*", "**/CONTRIBUTING*"],
            "extra_phrases": [],
        },
        "verification_gate": {
            "mode": "warn",
            "commands": [],  # regexes; empty = built-in list of common test/lint/typecheck commands
            "code_extensions": [".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs",
                                ".java", ".kt", ".cs", ".rb", ".php", ".swift", ".c", ".cc",
                                ".cpp", ".h", ".hpp", ".scala", ".ps1", ".sh", ".vue", ".svelte"],
        },
        "loop_detector": {
            "mode": "enforce",
            "repeat_threshold": 3,     # identical calls within the window
            "window": 12,
            "failure_threshold": 3,    # identical failing call N times in a row...
            "failure_window_minutes": 10,  # ...within this window...
            "failure_action": "ask",   # ...makes the next retry ask (or "deny")
            "reread_threshold": 4,     # same file read N times with no edit between
        },
    },
}


def user_config_path() -> str:
    return os.path.join(util.data_dir(), "config.json")


def project_config_path(project: str) -> str:
    return os.path.join(project, ".claude", "cchooks.json")


def _read_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise ConfigError("cannot parse %s: %s" % (path, e))


class ConfigError(Exception):
    pass


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> None:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v


def _tighten(base: Dict[str, Any], project: Dict[str, Any]) -> None:
    for name, over in (project.get("checks") or {}).items():
        if not isinstance(over, dict) or name not in base["checks"]:
            continue
        target = base["checks"][name]
        if name in USABILITY_CHECKS:
            _merge(target, over)
            continue
        m = over.get("mode")
        if m in MODES and MODES.index(m) > MODES.index(target.get("mode", "off")):
            target["mode"] = m
        for k in PROJECT_APPENDABLE & set(over):
            if isinstance(over[k], list) and isinstance(target.get(k), list):
                target[k] = target[k] + over[k]


def load(project: str = "") -> Dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    _merge(cfg, _read_json(user_config_path()))
    if project:
        _tighten(cfg, _read_json(project_config_path(project)))
    return cfg


def mode_of(cfg: Dict[str, Any], check: str) -> str:
    m = cfg["checks"].get(check, {}).get("mode", "off")
    return m if m in MODES else "warn"
