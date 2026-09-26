"""Install, uninstall, and health-check cchooks.

Runs under the interpreter the hooks will use, and writes that
interpreter's absolute path into exec-form hook entries, so no shell is
involved at hook time on any platform (bash, zsh, Git Bash, PowerShell).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, config, util

MARKER_ARG = "--cchooks"
EVENTS: List[Tuple[str, int]] = [
    ("SessionStart", 10),
    ("UserPromptSubmit", 10),
    ("PreToolUse", 20),
    ("PostToolUse", 20),
    ("PostToolUseFailure", 10),
    ("Stop", 30),
    ("SubagentStart", 10),
    ("SubagentStop", 30),
    ("ConfigChange", 10),
]
MIN_PY = (3, 9)


def lib_dir() -> str:
    return os.path.join(util.data_dir(), "lib")


def settings_path(scope: str, project: Optional[str]) -> str:
    if scope == "project":
        return os.path.join(project or os.getcwd(), ".claude", "settings.json")
    return os.path.join(util.claude_dir(), "settings.json")


def _load_settings(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return {}
    if not text.strip():
        return {}
    data = json.loads(text)  # let a malformed file abort the install loudly
    if not isinstance(data, dict):
        raise ValueError("%s is not a JSON object" % path)
    return data


def _write_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".cchooks.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _is_ours(handler: Any) -> bool:
    return isinstance(handler, dict) and MARKER_ARG in (handler.get("args") or [])


def strip_hooks(settings: Dict[str, Any]) -> int:
    removed = 0
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    for event in list(hooks):
        groups = hooks[event] if isinstance(hooks[event], list) else []
        new_groups = []
        for g in groups:
            inner = g.get("hooks", []) if isinstance(g, dict) else []
            keep = [h for h in inner if not _is_ours(h)]
            removed += len(inner) - len(keep)
            if keep:
                g = dict(g, hooks=keep)
                new_groups.append(g)
            elif not inner:
                new_groups.append(g)
        if new_groups:
            hooks[event] = new_groups
        else:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    return removed


def hook_entries(python: str) -> Dict[str, Any]:
    hook = os.path.join(lib_dir(), "hook.py")
    return {
        event: [{"hooks": [{"type": "command", "command": python, "args": ["-I", hook, event, MARKER_ARG],
                            "timeout": timeout}]}]
        for event, timeout in EVENTS
    }


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def _copy_lib(src_root: str) -> Dict[str, str]:
    dest = lib_dir()
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    for name in ("hook.py", "cli.py"):
        shutil.copy2(os.path.join(src_root, name), os.path.join(dest, name))
    shutil.copytree(os.path.join(src_root, "cchooks"), os.path.join(dest, "cchooks"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    manifest = {}
    for root, _dirs, files in os.walk(dest):
        for fn in files:
            if fn.endswith(".py"):
                p = os.path.join(root, fn)
                manifest[os.path.relpath(p, dest).replace("\\", "/")] = _sha256(p)
    return manifest


def _write_default_config(mode: Optional[str]) -> str:
    path = config.user_config_path()
    existing = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            existing = json.load(f)
    if mode:
        checks = existing.setdefault("checks", {})
        for name in config.DEFAULTS["checks"]:
            checks.setdefault(name, {})["mode"] = mode
    if mode or not os.path.exists(path):
        existing.setdefault("_comment", "Overrides for cchooks defaults. Modes: off | warn | enforce. "
                                        "See README for every setting.")
        _write_json(path, existing)
    return path


def _install_command(repo_root: str) -> Optional[str]:
    src = os.path.join(repo_root, "commands", "cchooks-report.md")
    if not os.path.exists(src):
        return None
    dest_dir = os.path.join(util.claude_dir(), "commands")
    os.makedirs(dest_dir, exist_ok=True)
    with open(src, "r", encoding="utf-8") as f:
        text = f.read().replace("{{CLI}}", '"%s" -I "%s"' % (sys.executable, os.path.join(lib_dir(), "cli.py")))
    dest = os.path.join(dest_dir, "cchooks-report.md")
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text)
    return dest


# ----------------------------------------------------------------- template
#
# A quickstart repo ships a starter ~/.claude (settings.json, CLAUDE.md,
# commands/, agents/, skills/ ...). Deploying it:
#   * settings.json is deep-merged into the user's: their existing values win,
#     lists (permission rules, hooks, ...) are unioned.
#   * any other file that already exists with different content is backed up
#     to <name>.bak-<timestamp> and replaced; identical files are left alone.

TEMPLATE_SKIP = {".DS_Store", "Thumbs.db", "__pycache__", ".git", "settings.local.json"}


def merge_settings(user: Any, starter: Any) -> Any:
    """Deep merge where the user's existing values win and lists are unioned."""
    if isinstance(user, dict) and isinstance(starter, dict):
        out = dict(user)
        for k, v in starter.items():
            out[k] = merge_settings(user[k], v) if k in user else v
        return out
    if isinstance(user, list) and isinstance(starter, list):
        seen = {json.dumps(x, sort_keys=True) for x in user}
        return list(user) + [x for x in starter if json.dumps(x, sort_keys=True) not in seen]
    return user


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.getsize(a) == os.path.getsize(b) and _sha256(a) == _sha256(b)
    except OSError:
        return False


def plan_template(template: str, dest: str) -> List[Tuple[str, str, str, str]]:
    """[(action, relpath, src, dst)] with action in create | replace | identical | merge."""
    plan = []
    for root, dirs, files in os.walk(template):
        dirs[:] = sorted(d for d in dirs if d not in TEMPLATE_SKIP)
        for fn in sorted(files):
            if fn in TEMPLATE_SKIP or ".bak-" in fn or fn.endswith(".pyc"):
                continue
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, template)
            dst = os.path.join(dest, rel)
            if rel == "settings.json":
                action = "merge"
            elif not os.path.exists(dst):
                action = "create"
            elif _same_file(src, dst):
                action = "identical"
            else:
                action = "replace"
            plan.append((action, rel, src, dst))
    return plan


def _backup(path: str, stamp: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    dest = "%s.bak-%s" % (path, stamp)
    if not os.path.exists(dest):
        shutil.copy2(path, dest)
    return dest


def apply_template(plan: List[Tuple[str, str, str, str]], stamp: str) -> None:
    for action, rel, src, dst in plan:
        if action in ("merge", "identical"):
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if action == "replace":
            print("  backed up   %s -> %s" % (rel, os.path.basename(_backup(dst, stamp) or "")))
        shutil.copy2(src, dst)
        print("  %-11s %s" % ("replaced" if action == "replace" else "added", rel))


def install(repo_root: str, scope: str = "user", project: Optional[str] = None, mode: Optional[str] = None,
            statusline: bool = False, template: Optional[str] = None, dry_run: bool = False) -> int:
    if sys.version_info < MIN_PY:
        print("cchooks needs Python %d.%d+; this is %s" % (MIN_PY + (sys.version.split()[0],)))
        return 1
    python = sys.executable
    if not python or not os.path.isabs(python):
        print("Could not determine an absolute path for this Python interpreter.")
        return 1
    if template and scope != "user":
        print("--template installs a starter ~/.claude and can't be combined with --scope project.")
        return 1
    spath = settings_path(scope, project)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    # Validate everything before writing anything.
    try:
        settings = _load_settings(spath)
    except (ValueError, OSError) as e:
        print("Refusing to touch %s: %s" % (spath, e))
        return 1
    plan: List[Tuple[str, str, str, str]] = []
    starter: Dict[str, Any] = {}
    if template:
        template = os.path.abspath(template)
        if not os.path.isdir(template):
            print("Template directory not found: %s" % template)
            return 1
        try:
            starter = _load_settings(os.path.join(template, "settings.json"))
        except (ValueError, OSError) as e:
            print("Template settings.json is invalid: %s" % e)
            return 1
        if starter.get("disableAllHooks"):
            print("Template settings.json sets disableAllHooks, which would switch off every hook. Remove it.")
            return 1
        plan = plan_template(template, util.claude_dir())
        print("Starter configuration from %s -> %s" % (template, util.claude_dir()))
        for action, rel, _s, _d in plan:
            label = {"merge": "merge into existing" if os.path.exists(spath) else "create",
                     "replace": "back up + replace", "create": "add", "identical": "unchanged"}[action]
            print("  %-20s %s" % (label, rel))
    if dry_run:
        print("Would register cchooks hooks for %s in %s using %s" % (", ".join(e for e, _ in EVENTS), spath, python))
        print("Dry run: nothing was changed.")
        return 0

    if plan:
        apply_template(plan, stamp)
    backup = _backup(spath, stamp)
    if backup:
        print("Backed up %s -> %s" % (spath, backup))
    if starter:
        settings = merge_settings(settings, starter)
    manifest = _copy_lib(os.path.join(repo_root, "src"))

    _authorize_config_change()  # our own edit must not trip an older install's tamper guard
    strip_hooks(settings)
    hooks = settings.setdefault("hooks", {})
    for event, groups in hook_entries(python).items():
        hooks.setdefault(event, []).extend(groups)
    notes = []
    if statusline:
        if settings.get("statusLine") and "cli.py" not in json.dumps(settings.get("statusLine")):
            notes.append("statusLine already configured; left it alone. Use `cli.py statusline` in yours.")
        elif util.IS_WINDOWS:
            notes.append("On Windows, add the status line by hand; see README (quoting differs per shell).")
        else:
            settings["statusLine"] = {"type": "command", "command": '"%s" -I "%s" statusline'
                                      % (python, os.path.join(lib_dir(), "cli.py"))}
    _write_json(spath, settings)

    prev = _install_info().get("settings_paths") or []
    info = {"version": __version__, "python": python, "lib_dir": lib_dir(), "settings_path": spath,
            "settings_paths": list(dict.fromkeys(prev + [spath])), "scope": scope, "installed_at": time.time(), "manifest": manifest}
    _write_json(os.path.join(util.data_dir(), "install.json"), info)
    cfg_path = _write_default_config(mode)
    cmd = _install_command(repo_root)

    print("Installed cchooks %s" % __version__)
    print("  interpreter : %s (Python %s)" % (python, sys.version.split()[0]))
    print("  code        : %s" % lib_dir())
    print("  hooks in    : %s" % spath)
    print("  config      : %s" % cfg_path)
    if cmd:
        print("  command     : /cchooks-report")
    for n in notes:
        print("  note        : " + n)
    ok = selftest(verbose=True)
    if not ok:
        print("\nSELF-TEST FAILED. The hooks are installed but not behaving; run `cli.py doctor`.")
        return 2
    print("\nSelf-test passed. Restart Claude Code (or open /hooks) to load the hooks.")
    return 0


def _authorize_config_change() -> None:
    os.makedirs(util.data_dir(), exist_ok=True)
    with open(os.path.join(util.data_dir(), "allow-config-change"), "w") as f:
        f.write(str(time.time()))


def _install_info() -> Dict[str, Any]:
    try:
        with open(os.path.join(util.data_dir(), "install.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def uninstall(keep_data: bool = False) -> int:
    """Remove everything cchooks added to ~/.claude.

    Removes: hook entries from every settings.json cchooks was installed into (and the user
    settings.json regardless), the cchooks status line, /cchooks-report, and ~/.claude/cchooks/
    (code, config, state, logs) unless keep_data. Never removes settings backups or files that
    came from a starter template: those are the user's.
    """
    info = _install_info()
    paths = list(dict.fromkeys(list(info.get("settings_paths") or [])
                               + [info.get("settings_path") or "", settings_path("user", None)]))
    _authorize_config_change()
    for spath in [p for p in paths if p]:
        if not os.path.exists(spath):
            continue
        try:
            settings = _load_settings(spath)
            n = strip_hooks(settings)
            sl = settings.get("statusLine")
            removed_sl = isinstance(sl, dict) and "cchooks" in json.dumps(sl)
            if removed_sl:
                settings.pop("statusLine")
            if n or removed_sl:
                _write_json(spath, settings)
            print("Removed %d cchooks hook entries%s from %s" % (n, " and the status line" if removed_sl else "", spath))
        except (OSError, ValueError) as e:
            print("Could not update %s: %s" % (spath, e))
    cmd = os.path.join(util.claude_dir(), "commands", "cchooks-report.md")
    if os.path.exists(cmd):
        os.remove(cmd)
        print("Removed /cchooks-report")
    if keep_data:
        shutil.rmtree(lib_dir(), ignore_errors=True)
        for fn in ("install.json", "allow-config-change"):
            try:
                os.remove(os.path.join(util.data_dir(), fn))
            except OSError:
                pass
        print("Removed code. Kept config, logs and state in %s." % util.data_dir())
    else:
        shutil.rmtree(util.data_dir(), ignore_errors=True)
        print("Deleted %s (code, config, state, logs)." % util.data_dir())
    print("Restart Claude Code (or open /hooks) so running sessions drop the hooks.")
    return 0


# ----------------------------------------------------------------- selftest

SELFTEST_CASES = [
    ("PreToolUse deny on rm -rf ~",
     {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}},
     lambda code, out: code == 0 and out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"),
    ("PreToolUse deny on Read ~/.ssh/id_rsa",
     {"hook_event_name": "PreToolUse", "tool_name": "Read",
      "tool_input": {"file_path": os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")}},
     lambda code, out: out.get("hookSpecificOutput", {}).get("permissionDecision") in ("deny", "ask")),
    ("UserPromptSubmit blocks a private key",
     {"hook_event_name": "UserPromptSubmit", "prompt": "here: -----BEGIN RSA " + "PRIVATE KEY-----\nabc"},
     lambda code, out: code == 2 and out.get("decision") == "block"),
    ("PreToolUse allows a harmless command",
     {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls -la"}},
     lambda code, out: code == 0 and not out.get("hookSpecificOutput", {}).get("permissionDecision")),
]


def selftest(verbose: bool = False) -> bool:
    info = {}
    try:
        with open(os.path.join(util.data_dir(), "install.json"), "r", encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, ValueError):
        pass
    python = info.get("python") or sys.executable
    hook = os.path.join(info.get("lib_dir") or lib_dir(), "hook.py")
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, CCHOOKS_HOME=tmp)
        # Tests the installed machinery (interpreter, code, output format), not the user's chosen
        # modes, so the tested checks are forced to enforce in an isolated home.
        forced = {"checks": {c: {"mode": "enforce"} for c in
                             ("prompt_gate", "sensitive_paths", "destructive_commands")}}
        with open(os.path.join(tmp, "config.json"), "w", encoding="utf-8") as f:
            json.dump(forced, f)
        for label, event, check in SELFTEST_CASES:
            event = dict(event, session_id="cchooks-selftest", cwd=tmp)
            try:
                r = subprocess.run([python, "-I", hook, event["hook_event_name"], MARKER_ARG],
                                   input=json.dumps(event).encode(), capture_output=True, timeout=30, env=env)
                out = json.loads(r.stdout.decode() or "{}")
                passed = bool(check(r.returncode, out))
            except (OSError, ValueError, subprocess.SubprocessError) as e:
                passed, r = False, None
                out = {"error": str(e)}
            ok &= passed
            if verbose or not passed:
                print("  [%s] %s" % ("ok" if passed else "FAIL", label))
                if not passed:
                    print("        exit=%s out=%s err=%s" % (getattr(r, "returncode", "?"), out,
                                                             (getattr(r, "stderr", b"") or b"").decode()[:300]))
    if verbose:
        try:
            cfg = config.load("")
            soft = ["%s=%s" % (c, config.mode_of(cfg, c)) for c in config.SECURITY_CHECKS
                    if config.mode_of(cfg, c) != "enforce"]
            if soft:
                print("  note: security checks not enforcing in your config: " + ", ".join(soft))
        except config.ConfigError as e:
            print("  PROBLEM: " + str(e))
    return ok


def doctor() -> int:
    problems = []
    info = {}
    try:
        with open(os.path.join(util.data_dir(), "install.json"), "r", encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, ValueError):
        problems.append("not installed (no install.json)")
    py = info.get("python")
    if py and not os.path.exists(py):
        problems.append("interpreter %s no longer exists (Python upgraded or moved?). Re-run the installer." % py)
    spath = info.get("settings_path")
    if spath:
        try:
            s = _load_settings(spath)
            present = {e for e, groups in (s.get("hooks") or {}).items()
                       for g in groups if isinstance(g, dict) for h in g.get("hooks", []) if _is_ours(h)}
            missing = [e for e, _ in EVENTS if e not in present]
            if missing:
                problems.append("hooks missing from %s for: %s" % (spath, ", ".join(missing)))
            if s.get("disableAllHooks"):
                problems.append("disableAllHooks is true in %s" % spath)
        except (OSError, ValueError) as e:
            problems.append("cannot read %s: %s" % (spath, e))
    from .checks.tamper_guard import verify_manifest
    problems += ["file " + p for p in verify_manifest()]
    try:
        config.load(os.getcwd())
    except config.ConfigError as e:
        problems.append(str(e))
    print("cchooks %s  data=%s" % (__version__, util.data_dir()))
    for p in problems:
        print("  PROBLEM: " + p)
    ok = selftest(verbose=True)
    if not problems and ok:
        print("All good.")
    return 0 if (ok and not problems) else 1
