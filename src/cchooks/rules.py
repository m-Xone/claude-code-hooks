"""Custom rules: small declarative hooks, one JSON file each.

A rule says *when* to look (an event, optionally some tools), *what* to look
for (one or more conditions, all of which must hold) and *what to do*. Rules
can only ever make Claude Code stricter: there is no "allow" action, so a
rule written by a compromised agent or shipped by a hostile repository can
at worst be annoying, never open a hole.

    {
      "id": "no-prod-kubectl",
      "description": "kubectl against the prod context needs a human",
      "event": "PreToolUse",
      "tools": ["Bash", "PowerShell"],
      "when": [
        {"field": "command", "words": ["kubectl"]},
        {"field": "command", "regex": "--context[= ]prod"},
        {"field": "command", "words": ["--dry-run"], "not": true}
      ],
      "action": "ask",
      "message": "kubectl against prod.",
      "mode": "warn"
    }

User rules live in <data dir>/rules/*.json. A project may add rules in
<project>/.claude/cchooks-rules/*.json, but those may not use regexes: a
catastrophic-backtracking pattern would time the hook out, and a timed-out
hook lets the action through.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import util

SCHEMA = 1
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MAX_SCAN = 512_000        # characters of any one value a rule looks at
MAX_RULES = 200           # per location; beyond this the rest are ignored

# Which fields exist at which event, and what each event can do.
FIELDS: Dict[str, Tuple[str, ...]] = {
    "UserPromptSubmit": ("prompt",),
    "PreToolUse": ("command", "path", "content", "url", "input"),
    "PostToolUse": ("command", "path", "url", "input", "output"),
    "Stop": ("message",),
    "SubagentStop": ("message",),
}
ACTIONS: Dict[str, Tuple[str, ...]] = {
    "UserPromptSubmit": ("block", "warn", "context"),
    "PreToolUse": ("deny", "ask", "warn", "context"),
    "PostToolUse": ("redact", "warn", "context"),
    "Stop": ("block", "warn"),
    "SubagentStop": ("block", "warn"),
}
KINDS = ("regex", "words", "glob", "detector")
DETECTORS = ("secrets", "pii", "injection")
RULE_KEYS = {"schema", "id", "description", "event", "tools", "when", "action", "message", "mode",
             "override", "tests"}
COND_KEYS = {"field", "not", "case_sensitive", "min_score"} | set(KINDS)

SHELL_TOOLS = ("Bash", "PowerShell")
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>`|;)]{1,2000}", re.IGNORECASE)


class RuleError(ValueError):
    pass


@dataclass
class Condition:
    field: str
    kind: str
    value: Any
    negate: bool = False
    rx: Optional["re.Pattern[str]"] = None
    min_score: int = 3


@dataclass
class Rule:
    id: str
    event: str
    action: str
    message: str
    conditions: List[Condition]
    tools: List[str] = field(default_factory=list)
    mode: str = "warn"
    override: bool = True
    description: str = ""
    source: str = ""          # file it came from
    origin: str = "user"      # user | project
    tests: Dict[str, List[Any]] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return ("rule:" if self.origin == "user" else "project-rule:") + self.id


# ------------------------------------------------------------------ parsing

def _words_regex(words: List[str], case_sensitive: bool) -> "re.Pattern[str]":
    alts = "|".join(re.escape(w) for w in sorted(set(words), key=len, reverse=True))
    return re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])" % alts, 0 if case_sensitive else re.IGNORECASE)


# Nested quantifiers such as (a+)+ or (\w*)* are the classic catastrophic-backtracking shape.
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*?(?<!\\)[+*](?:[^()\\]|\\.)*\)[+*{]")


def regex_risk(pattern: str) -> Optional[str]:
    """A reason this regex could hang on hostile input, or None. A heuristic, not a proof."""
    if len(pattern) > 2000:
        return "longer than 2000 characters"
    if _NESTED_QUANT.search(pattern):
        return "nested quantifier (like (a+)+), which can take exponential time"
    if re.search(r"(?:\.\*|\\S\*|\\w\*|\.\+|\\S\+|\\w\+)\s*(?:\.\*|\\S\*|\\w\*|\.\+|\\S\+|\\w\+)", pattern):
        return "two adjacent unbounded repeats (like .*.*), which can take quadratic time"
    return None


def parse(data: Any, origin: str = "user", source: str = "") -> Rule:
    """Validate one rule document. Raises RuleError with a message a person can act on."""
    if not isinstance(data, dict):
        raise RuleError("a rule must be a JSON object")
    unknown = set(data) - RULE_KEYS
    if unknown:
        raise RuleError("unknown key(s): %s" % ", ".join(sorted(unknown)))
    if data.get("schema", SCHEMA) != SCHEMA:
        raise RuleError("schema %r is not supported (expected %d)" % (data.get("schema"), SCHEMA))

    rid = data.get("id")
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise RuleError("id must be 1-48 lowercase letters, digits, - or _, starting with a letter or digit")
    event = data.get("event")
    if event not in FIELDS:
        raise RuleError("event must be one of: %s" % ", ".join(FIELDS))
    action = data.get("action")
    if action not in ACTIONS[event]:
        raise RuleError("action for %s must be one of: %s" % (event, ", ".join(ACTIONS[event])))
    message = data.get("message")
    if not isinstance(message, str) or not message.strip():
        raise RuleError("message is required: it is what Claude or the user sees when the rule fires")
    mode = data.get("mode", "warn")
    if mode not in ("off", "warn", "enforce"):
        raise RuleError("mode must be off, warn or enforce")

    tools = data.get("tools", [])
    if isinstance(tools, str):
        tools = [tools]
    if not isinstance(tools, list) or not all(isinstance(t, str) and t for t in tools):
        raise RuleError("tools must be a list of tool names (globs like mcp__* are allowed)")
    if tools and event not in ("PreToolUse", "PostToolUse"):
        raise RuleError("tools only applies to PreToolUse and PostToolUse rules")

    when = data.get("when")
    if isinstance(when, dict):
        when = [when]
    if not isinstance(when, list) or not when:
        raise RuleError("when must be a non-empty list of conditions")
    conds = [_parse_condition(c, i, event, origin) for i, c in enumerate(when, 1)]
    if all(c.negate for c in conds):
        raise RuleError("at least one condition must be positive (without \"not\"), or the rule fires on everything")
    if action == "redact" and not any(c.field == "output" and not c.negate and c.kind in ("regex", "words", "detector")
                                      and c.value != "injection" for c in conds):
        raise RuleError("redact needs a positive regex, words or secrets/pii detector condition on the output field")

    tests = data.get("tests", {})
    if not isinstance(tests, dict) or any(k not in ("hit", "miss") or not isinstance(v, list) for k, v in tests.items()):
        raise RuleError("tests must look like {\"hit\": [...], \"miss\": [...]}")

    return Rule(id=rid, event=event, action=action, message=message.strip(), conditions=conds, tools=tools,
                mode=mode, override=bool(data.get("override", True)), description=str(data.get("description", "")),
                source=source, origin=origin, tests=tests)


def _parse_condition(c: Any, i: int, event: str, origin: str) -> Condition:
    where = "condition %d" % i
    if not isinstance(c, dict):
        raise RuleError("%s must be an object" % where)
    unknown = set(c) - COND_KEYS
    if unknown:
        raise RuleError("%s: unknown key(s): %s" % (where, ", ".join(sorted(unknown))))
    fld = c.get("field")
    if fld not in FIELDS[event]:
        raise RuleError("%s: field for %s must be one of: %s" % (where, event, ", ".join(FIELDS[event])))
    kinds = [k for k in KINDS if k in c]
    if len(kinds) != 1:
        raise RuleError("%s: needs exactly one of %s" % (where, ", ".join(KINDS)))
    kind, value = kinds[0], c[kinds[0]]
    cond = Condition(field=fld, kind=kind, value=value, negate=bool(c.get("not", False)))
    cs = bool(c.get("case_sensitive", False))

    if kind == "regex":
        if origin != "user":
            raise RuleError("%s: project rules cannot use regex (use words, glob or detector)" % where)
        if not isinstance(value, str) or not value:
            raise RuleError("%s: regex must be a non-empty string" % where)
        risk = regex_risk(value)
        if risk:
            raise RuleError("%s: regex rejected: %s" % (where, risk))
        try:
            cond.rx = re.compile(value, re.MULTILINE | (0 if cs else re.IGNORECASE))
        except re.error as e:
            raise RuleError("%s: invalid regex: %s" % (where, e))
    elif kind == "words":
        if isinstance(value, str):
            value = cond.value = [value]
        if not isinstance(value, list) or not value or not all(isinstance(w, str) and w.strip() for w in value):
            raise RuleError("%s: words must be a non-empty list of strings" % where)
        if len(value) > 500:
            raise RuleError("%s: at most 500 words per condition" % where)
        cond.rx = _words_regex(value, cs)
    elif kind == "glob":
        if isinstance(value, str):
            value = cond.value = [value]
        if fld != "path":
            raise RuleError("%s: glob only works on the path field" % where)
        if not isinstance(value, list) or not value or not all(isinstance(g, str) and g for g in value):
            raise RuleError("%s: glob must be a non-empty list of patterns" % where)
    elif kind == "detector":
        if value not in DETECTORS:
            raise RuleError("%s: detector must be one of: %s" % (where, ", ".join(DETECTORS)))
        try:
            cond.min_score = int(c.get("min_score", 3))
        except (TypeError, ValueError):
            raise RuleError("%s: min_score must be a number" % where)
    return cond


# ------------------------------------------------------------------ loading

def user_rules_dir() -> str:
    return os.path.join(util.data_dir(), "rules")


def project_rules_dir(project: str) -> str:
    return os.path.join(project, ".claude", "cchooks-rules")


def load_dir(path: str, origin: str) -> Tuple[List[Rule], List[str]]:
    """(valid rules, human-readable problems). Never raises."""
    rules: List[Rule] = []
    problems: List[str] = []
    try:
        names = sorted(n for n in os.listdir(path) if n.endswith(".json"))
    except OSError:
        return rules, problems
    if len(names) > MAX_RULES:
        problems.append("%s: only the first %d rule files are used" % (path, MAX_RULES))
        names = names[:MAX_RULES]
    seen = set()
    for n in names:
        p = os.path.join(path, n)
        try:
            with open(p, "r", encoding="utf-8") as f:
                rule = parse(json.load(f), origin=origin, source=p)
        except (OSError, ValueError) as e:  # RuleError is a ValueError, as is bad JSON
            problems.append("%s: %s" % (n, e))
            continue
        if rule.id in seen:
            problems.append("%s: duplicate id '%s'" % (n, rule.id))
            continue
        seen.add(rule.id)
        rules.append(rule)
    return rules, problems


def load_all(project: str, include_project: bool = True) -> Tuple[List[Rule], List[str]]:
    rules, problems = load_dir(user_rules_dir(), "user")
    if include_project and project:
        more, p2 = load_dir(project_rules_dir(project), "project")
        rules += more
        problems += ["project " + p for p in p2]
    return rules, problems


# --------------------------------------------------------------- evaluation

def _strings(obj: Any, out: List[str], depth: int = 0) -> List[str]:
    if depth > 20:
        return out
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _strings(v, out, depth + 1)
    return out


def field_values(event: Dict[str, Any], fld: str) -> List[str]:
    """The strings a condition on `fld` looks at, for this event."""
    ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    tool = event.get("tool_name") or ""
    cmd = ti.get("command") if tool in SHELL_TOOLS and isinstance(ti.get("command"), str) else ""
    if fld == "prompt":
        v = event.get("prompt")
        return [v] if isinstance(v, str) else []
    if fld == "message":
        v = event.get("last_assistant_message")
        return [v] if isinstance(v, str) else []
    if fld == "command":
        return [cmd] if cmd else []
    if fld == "content":
        vals = [ti.get(k) for k in ("content", "new_string", "new_source")]
        for e in ti.get("edits") or []:
            if isinstance(e, dict):
                vals.append(e.get("new_string"))
        return [v for v in vals if isinstance(v, str) and v]
    if fld == "url":
        vals = [ti.get("url")] if isinstance(ti.get("url"), str) else []
        return vals + URL_RE.findall(cmd)
    if fld == "path":
        cwd = util.norm_path(event.get("cwd") or os.getcwd())
        raw = [ti.get(k) for k in ("file_path", "notebook_path", "path")]
        paths = [util.norm_path(r, cwd) for r in raw if isinstance(r, str) and r]
        if cmd:
            from .checks.sensitive_paths import _candidate_tokens
            paths += [util.norm_path(t, cwd) for t in _candidate_tokens(util.neutralize(cmd))]
        return [p for p in paths if p]
    if fld == "input":
        return _strings(ti, [])
    if fld == "output":
        return _strings(event.get("tool_response"), [])
    return []


def _cond_matches(c: Condition, values: List[str]) -> bool:
    for v in values:
        v = v[:MAX_SCAN]
        if c.kind in ("regex", "words"):
            if c.rx.search(v):
                return True
        elif c.kind == "glob":
            if util.path_matches(v, c.value) or util.path_matches(v.rstrip("/") + "/", c.value):
                return True
        elif c.kind == "detector":
            if c.value == "injection":
                from .detectors import injection
                if injection.score(injection.scan(v)) >= c.min_score:
                    return True
            else:
                from .detectors import secrets
                if secrets.scan(v, secrets=c.value == "secrets", pii=c.value == "pii", max_len=MAX_SCAN):
                    return True
    return False


def applies(rule: Rule, event: Dict[str, Any]) -> bool:
    if rule.event != event.get("hook_event_name"):
        return False
    if rule.tools:
        tool = event.get("tool_name") or ""
        if not any(fnmatch.fnmatchcase(tool, t) for t in rule.tools):
            return False
    return True


def matches(rule: Rule, event: Dict[str, Any]) -> bool:
    if not applies(rule, event):
        return False
    cache: Dict[str, List[str]] = {}
    for c in rule.conditions:
        if c.field not in cache:
            cache[c.field] = field_values(event, c.field)
        if _cond_matches(c, cache[c.field]) == c.negate:
            return False
    return True


def redact(rule: Rule, response: Any) -> Tuple[Any, int]:
    """(tool_response with this rule's output matches replaced, number replaced). Shape is kept."""
    count = 0
    conds = [c for c in rule.conditions if c.field == "output" and not c.negate]
    tag = "[REDACTED:%s]" % rule.id

    def scrub(s: str) -> str:
        nonlocal count
        head, tail = s[:MAX_SCAN], s[MAX_SCAN:]
        for c in conds:
            if c.kind in ("regex", "words"):
                head, n = c.rx.subn(tag, head)
                count += n
            elif c.kind == "detector" and c.value in ("secrets", "pii"):
                from .detectors import secrets
                found = secrets.scan(head, secrets=c.value == "secrets", pii=c.value == "pii", max_len=MAX_SCAN)
                count += len(found)
                head = secrets.redact_text(head, found)
        return head + tail

    return util.map_strings(response, scrub), count


# ---------------------------------------------------------------- describe

_EVENT_WORDS = {
    "UserPromptSubmit": "you submit a prompt",
    "PreToolUse": "Claude is about to use %s",
    "PostToolUse": "%s returns its result",
    "Stop": "Claude finishes a reply",
    "SubagentStop": "a subagent finishes",
}
_FIELD_WORDS = {
    "prompt": "the prompt", "command": "the shell command", "path": "a file path", "content": "the text being written",
    "url": "a URL", "input": "any tool argument", "output": "the tool's output", "message": "the reply",
}
_DETECTOR_WORDS = {"secrets": "contains a secret", "pii": "contains personal data",
                   "injection": "looks like a prompt injection"}


def _cond_words(c: Condition) -> str:
    neg = c.negate
    if c.kind == "words":
        ws = ", ".join('"%s"' % w for w in c.value[:5]) + (" (+%d more)" % (len(c.value) - 5) if len(c.value) > 5 else "")
        verb = ("does not contain " if neg else "contains ") + ("the word " if len(c.value) == 1 else "any of ")
        return "%s %s%s" % (_FIELD_WORDS[c.field], verb, ws)
    if c.kind == "regex":
        return "%s %s /%s/" % (_FIELD_WORDS[c.field], "does not match" if neg else "matches", c.value)
    if c.kind == "glob":
        return "%s %s %s" % (_FIELD_WORDS[c.field], "is not under" if neg else "is under",
                              " or ".join(c.value[:4]))
    what = _DETECTOR_WORDS[c.value]
    return "%s %s" % (_FIELD_WORDS[c.field], what.replace("contains", "does not contain").replace(
        "looks like", "does not look like") if neg else what)


def describe(rule: Rule) -> str:
    """One plain-English sentence, for review screens and permission prompts."""
    who = " or ".join(rule.tools) if rule.tools else "any tool"
    when = _EVENT_WORDS[rule.event] % who if "%s" in _EVENT_WORDS[rule.event] else _EVENT_WORDS[rule.event]
    conds = " and ".join(_cond_words(c) for c in rule.conditions)
    do = {
        "block": "hold the prompt back" if rule.event == "UserPromptSubmit" else "make Claude keep working",
        "deny": "block the tool call", "ask": "ask you first", "warn": "show you a warning",
        "context": "pass a note to Claude", "redact": "redact the matches before Claude sees them",
    }[rule.action]
    return 'When %s, if %s: %s with "%s" (%s mode).' % (when, conds, do, rule.message, rule.mode)
