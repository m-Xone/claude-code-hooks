"""Tools for writing custom rules: test a draft, replay it against past
sessions, install it, change its mode. Used by `cli.py rule ...` and the
/cchooks-new wizard. Never imported by the hooks themselves.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import rules as R
from . import state, util
from .detectors import secrets

DEFAULT_TOOL = {"command": "Bash", "path": "Read", "content": "Write", "url": "WebFetch", "input": "mcp__example__tool",
                "output": "Bash"}


def drafts_dir() -> str:
    """Where the wizard writes drafts: outside the protected cchooks folder, so Claude can write there."""
    return os.path.join(tempfile.gettempdir(), "cchooks-drafts")


def load_file(path: str, origin: str = "user") -> R.Rule:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise R.RuleError("cannot read %s: %s" % (path, e))
    except ValueError as e:
        raise R.RuleError("%s is not valid JSON: %s" % (path, e))
    return R.parse(data, origin=origin, source=path)


# -------------------------------------------------------------------- tests

def sample_event(rule: R.Rule, sample: Any, cwd: str) -> Dict[str, Any]:
    """Turn a test sample into the event the rule would see.

    A string goes into the field of the rule's first positive condition; a dict is used as the
    event itself (for rules that look at more than one field)."""
    ev: Dict[str, Any] = {"hook_event_name": rule.event, "session_id": "rule-test", "cwd": cwd}
    if isinstance(sample, dict):
        ev.update(sample)
        return ev
    text = str(sample)
    fld = next(c.field for c in rule.conditions if not c.negate)
    concrete = [t for t in rule.tools if not any(ch in t for ch in "*?[")]
    tool = concrete[0] if concrete else DEFAULT_TOOL.get(fld, "Bash")
    shell = tool in R.SHELL_TOOLS
    if fld == "prompt":
        ev["prompt"] = text
    elif fld == "message":
        ev["last_assistant_message"] = text
    else:
        ev["tool_name"] = tool
        if fld == "command":
            ti = {"command": text}
        elif fld == "path":
            ti = {"command": "cat " + text} if shell else {"file_path": text}
        elif fld == "content":
            ti = {"command": "cat > out.txt <<'EOF'\n%s\nEOF" % text} if shell else {"file_path": "out.txt", "content": text}
        elif fld == "url":
            ti = {"command": "curl " + text} if shell else {"url": text, "prompt": "summarize"}
        elif fld == "output":
            ti = {"command": "cat data.txt"} if shell else {}
            ev["tool_response"] = {"stdout": text, "stderr": ""}
        else:
            ti = {"command": text} if shell else {"text": text}
        ev["tool_input"] = ti
    return ev


def run_tests(rule: R.Rule, cwd: str) -> List[Tuple[str, Any, bool]]:
    """[(expected 'hit'|'miss', sample, passed)]"""
    out = []
    for expect in ("hit", "miss"):
        for sample in rule.tests.get(expect, []):
            got = R.matches(rule, sample_event(rule, sample, cwd))
            out.append((expect, sample, got == (expect == "hit")))
    return out


_TIMING_PROBE = r"""
import re, sys, time, json
pats = json.loads(sys.argv[1])
chars = "".join(sorted(set(re.sub(r"\\.|[\[\]\(\)\{\}\?\*\+\|\^\$]", "", "".join(pats)))))[:20] or "a"
inputs = ["a" * 20000, "a" * 20000 + "!", " " * 20000, "0" * 20000, "\n" * 20000, "aA0 _-./:=" * 2000,
          chars * (20000 // max(1, len(chars))), (chars + " ") * (20000 // (len(chars) + 1)) + "!"]
worst = 0.0
for p in pats:
    rx = re.compile(p, re.MULTILINE | re.IGNORECASE)
    for s in inputs:
        t = time.perf_counter(); rx.search(s); worst = max(worst, time.perf_counter() - t)
print(worst)
"""


def timing_check(rule: R.Rule, limit: float = 3.0) -> Tuple[str, str]:
    """('ok'|'slow'|'hang', detail). Runs the regexes against worst-case inputs in a child process
    so a pattern that hangs can be killed."""
    pats = [c.value for c in rule.conditions if c.kind == "regex"]
    if not pats:
        return "ok", "no regexes"
    try:
        r = subprocess.run([sys.executable, "-I", "-c", _TIMING_PROBE, json.dumps(pats)],
                           capture_output=True, text=True, timeout=limit)
        worst = float(r.stdout.strip() or "nan")
    except subprocess.TimeoutExpired:
        return "hang", "a regex took over %.0fs on a 20 KB worst-case input; hooks time out and let actions through" % limit
    except ValueError:
        return "ok", "could not time the regexes"
    if worst > 0.25:
        return "slow", "worst case %.0f ms on a 20 KB input; tool output can be much larger" % (worst * 1000)
    return "ok", "worst case %.1f ms on a 20 KB input" % (worst * 1000)


# ------------------------------------------------------------------- replay

def transcripts_dir(project: str) -> str:
    return os.path.join(util.claude_dir(), "projects", re.sub(r"[^A-Za-z0-9]", "-", project))


def _transcript_files(project: str, sessions: int, all_projects: bool) -> List[str]:
    roots = []
    base = os.path.join(util.claude_dir(), "projects")
    if all_projects:
        try:
            roots = [os.path.join(base, d) for d in os.listdir(base)]
        except OSError:
            roots = []
    else:
        roots = [transcripts_dir(project)]
    files = []
    for r in roots:
        try:
            files += [os.path.join(r, n) for n in os.listdir(r) if n.endswith(".jsonl")]
        except OSError:
            continue
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return files[:sessions]


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def events_from_transcript(path: str) -> Iterator[Dict[str, Any]]:
    """Rebuild the hook events a past session produced, as closely as the transcript allows."""
    tools: Dict[str, Tuple[str, Any]] = {}
    sid = os.path.splitext(os.path.basename(path))[0]
    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with f:
        for line in f:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if not isinstance(d, dict) or d.get("type") not in ("user", "assistant") or d.get("isSidechain"):
                continue
            msg = d.get("message") or {}
            content = msg.get("content")
            base = {"session_id": sid, "cwd": d.get("cwd") or "", "_ts": d.get("timestamp", "")}
            if d["type"] == "user":
                if isinstance(content, str):
                    if not d.get("isMeta") and not content.lstrip().startswith("<"):
                        yield dict(base, hook_event_name="UserPromptSubmit", prompt=content)
                    continue
                for b in content or []:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "tool_result" and b.get("tool_use_id") in tools:
                        name, ti = tools.pop(b["tool_use_id"])
                        resp = d.get("toolUseResult")
                        if resp is None or isinstance(resp, (bool, int, float)):
                            resp = _text_of(b.get("content"))
                        yield dict(base, hook_event_name="PostToolUse", tool_name=name, tool_input=ti, tool_response=resp)
                    elif b.get("type") == "text" and not d.get("isMeta") and not b.get("text", "").startswith("["):
                        yield dict(base, hook_event_name="UserPromptSubmit", prompt=b.get("text", ""))
            else:
                for b in content if isinstance(content, list) else []:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "tool_use":
                        tools[b.get("id")] = (b.get("name") or "", b.get("input") or {})
                        yield dict(base, hook_event_name="PreToolUse", tool_name=b.get("name") or "",
                                   tool_input=b.get("input") or {}, tool_use_id=b.get("id"))
                    elif b.get("type") == "text" and b.get("text", "").strip():
                        yield dict(base, hook_event_name="Stop", last_assistant_message=b["text"])


def _snippet(rule: R.Rule, ev: Dict[str, Any]) -> str:
    fld = next(c.field for c in rule.conditions if not c.negate)
    vals = R.field_values(ev, fld)
    text = vals[0] if vals else ""
    for c in rule.conditions:  # centre the snippet on the first match we can locate
        if c.rx is not None and not c.negate:
            for v in vals:
                m = c.rx.search(v[:R.MAX_SCAN])
                if m:
                    text = v[max(0, m.start() - 40): m.end() + 60]
                    break
            break
    found = secrets.scan(text, secrets=True, pii=True)
    return util.truncate(secrets.redact_text(text, found), 110)


def replay(rule: R.Rule, project: str, sessions: int = 20, all_projects: bool = False,
           examples: int = 5) -> Dict[str, Any]:
    files = _transcript_files(project, sessions, all_projects)
    seen = hits = 0
    per_session: Dict[str, int] = {}
    samples: List[str] = []
    event = "SubagentStop" if rule.event == "SubagentStop" else rule.event
    t0 = time.perf_counter()
    for path in files:
        for ev in events_from_transcript(path):
            if event == "SubagentStop" and ev["hook_event_name"] == "Stop":
                continue  # subagent transcripts are not replayed
            if ev["hook_event_name"] != event:
                continue
            seen += 1
            if not R.matches(rule, ev):
                continue
            hits += 1
            per_session[ev["session_id"]] = per_session.get(ev["session_id"], 0) + 1
            if len(samples) < examples:
                label = ev.get("tool_name") or {"UserPromptSubmit": "prompt", "Stop": "reply"}.get(event, event)
                samples.append("%s  %-10s %s" % (str(ev.get("_ts", ""))[:10], label, _snippet(rule, ev)))
    return {"sessions": len(files), "events": seen, "hits": hits, "sessions_hit": len(per_session),
            "examples": samples, "seconds": time.perf_counter() - t0,
            "where": "all projects" if all_projects else transcripts_dir(project)}


# ------------------------------------------------------------------ install

def rule_path(rule_id: str) -> str:
    return os.path.join(R.user_rules_dir(), rule_id + ".json")


def add(path: str, replace: bool = False) -> Tuple[bool, str]:
    rule = load_file(path)
    failed = [t for t in run_tests(rule, os.getcwd()) if not t[2]]
    if failed:
        return False, "not installed: %d test example(s) fail. Run `rule test` first." % len(failed)
    verdict, detail = timing_check(rule)
    if verdict == "hang":
        return False, "not installed: " + detail
    dest = rule_path(rule.id)
    if os.path.exists(dest) and not replace:
        return False, "not installed: a rule called '%s' already exists (use --replace to overwrite it)" % rule.id
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("mode", "warn")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    _write(dest, data)
    state.audit({"session_id": "cli"}, "custom_rules", "rule-added", R.describe(load_file(dest)))
    return True, dest


def _write(path: str, data: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def set_mode(rule_id: str, mode: str) -> Tuple[bool, str]:
    if mode not in ("off", "warn", "enforce"):
        return False, "mode must be off, warn or enforce"
    p = rule_path(rule_id)
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return False, "no usable rule '%s' (%s)" % (rule_id, e)
    data["mode"] = mode
    _write(p, data)
    state.audit({"session_id": "cli"}, "custom_rules", "rule-mode", "%s -> %s" % (rule_id, mode))
    return True, p


def remove(rule_id: str) -> Tuple[bool, str]:
    p = rule_path(rule_id)
    if not os.path.exists(p):
        return False, "no rule '%s'" % rule_id
    os.remove(p)
    state.audit({"session_id": "cli"}, "custom_rules", "rule-removed", rule_id)
    return True, p


def find_draft(rule_id_or_path: str) -> Optional[str]:
    if os.path.exists(rule_id_or_path):
        return rule_id_or_path
    p = rule_path(rule_id_or_path)
    return p if os.path.exists(p) else None
