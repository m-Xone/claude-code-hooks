"""Small cross-platform helpers shared by every check."""

from __future__ import annotations

import json
import math
import os
import re
import shlex
from collections import Counter
from typing import Any, Iterator, List, Optional

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------- locations

def home() -> str:
    return os.path.expanduser("~")


def _installed_home() -> str:
    """<claude dir>/cchooks when running from an installed copy (<claude dir>/cchooks/lib/cchooks/)."""
    lib = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.basename(lib) == "lib" and os.path.exists(os.path.join(lib, "hook.py")):
        return os.path.dirname(lib)
    return ""


def data_dir() -> str:
    """Root for config, state and logs: CCHOOKS_HOME, else wherever this copy is installed,
    else <claude dir>/cchooks."""
    return os.environ.get("CCHOOKS_HOME") or _installed_home() or os.path.join(claude_dir(), "cchooks")


def cli_hint(sub: str = "") -> str:
    """How the user invokes the cchooks CLI (shown in messages)."""
    exe = "py -3" if IS_WINDOWS else "python3"
    return ("%s \"%s\" %s" % (exe, os.path.join(data_dir(), "lib", "cli.py"), sub)).strip()


def claude_dir() -> str:
    """The Claude Code config folder: CLAUDE_CONFIG_DIR, else the folder this copy is installed
    in (so hooks keep working if the variable isn't passed through), else ~/.claude."""
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        return os.path.expanduser(os.environ["CLAUDE_CONFIG_DIR"])
    installed = _installed_home()
    return os.path.dirname(installed) if installed else os.path.join(home(), ".claude")


# -------------------------------------------------------------------- paths

def norm_path(p: str, cwd: Optional[str] = None) -> str:
    """Absolute, forward-slash, user-expanded path. Case preserved."""
    if not isinstance(p, str) or not p:
        return ""
    p = p.strip().strip("'\"")
    if IS_WINDOWS or os.environ.get("CCHOOKS_GITBASH_PATHS"):
        p = re.sub(r"^/([A-Za-z])(?=/|$)", r"\1:", p)  # Git Bash /c/Users -> C:/Users
    p = expand_vars(p)
    p = os.path.expanduser(p)
    if not os.path.isabs(p) and not re.match(r"^[A-Za-z]:[\\/]", p):
        p = os.path.join(cwd or os.getcwd(), p)
    p = os.path.normpath(p)
    return p.replace("\\", "/")


def expand_vars(s: str) -> str:
    """Expand the home-directory spellings used by bash, cmd and PowerShell."""
    h = home()
    for pat in (r"\$\{HOME\}", r"\$HOME\b", r"\$env:USERPROFILE\b", r"\$env:HOME\b",
                r"%USERPROFILE%", r"%HOMEPATH%"):
        s = re.sub(pat, lambda _m: h, s, flags=re.IGNORECASE)
    return s


def is_within(path: str, root: str) -> bool:
    if not path or not root:
        return False
    a, b = path.rstrip("/").lower(), root.rstrip("/").lower()
    return a == b or a.startswith(b + "/")


def project_dir(event: dict) -> str:
    return norm_path(os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd())


_glob_cache = {}


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
    """Glob with ** support, matched case-insensitively against normalized paths.

    Patterns starting with ~ are anchored at the home directory; patterns
    starting with **/ match at any depth; a bare name matches any basename.
    """
    cached = _glob_cache.get(pattern)
    if cached is not None:
        return cached
    pat = pattern.replace("\\", "/")
    if pat.startswith("~"):
        pat = home().replace("\\", "/") + pat[1:]
    elif "/" not in pat:
        pat = "**/" + pat
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    rx = re.compile("^" + "".join(out) + "$", re.IGNORECASE)
    _glob_cache[pattern] = rx
    return rx


def path_matches(path: str, patterns: List[str]) -> Optional[str]:
    for p in patterns:
        if glob_to_regex(p).match(path):
            return p
    return None


# -------------------------------------------------------------------- shell

_SPLIT_RE = re.compile(r"\|\||&&|;|\||\n|&(?!>)")


def split_commands(cmd: str) -> List[str]:
    """Split a shell line into rough sub-commands, including $() and backticks.

    Deliberately over-splits: a check that sees too many segments costs
    nothing, one that sees too few misses things.
    """
    parts = [cmd]
    parts += re.findall(r"\$\(([^()]*)\)", cmd)
    parts += re.findall(r"`([^`]*)`", cmd)
    # bash -c "..." / pwsh -Command "..." / eval "..."
    parts += [m[1] for m in re.findall(
        r"(?:\b(?:ba|z|k|da)?sh|\bpwsh|\bpowershell(?:\.exe)?|\bcmd(?:\.exe)?)\s+(?:-\w+\s+)*"
        r"(?:-[A-Za-z]*c|-Command|/c)\s+(['\"])(.*?)\1", cmd, flags=re.IGNORECASE | re.DOTALL)]
    parts += [m[1] for m in re.findall(r"\beval\s+(['\"])(.*?)\1", cmd, flags=re.DOTALL)]
    # echo 'rm -rf ~' | sh  -- text piped into a shell is code
    parts += [m[1] for m in re.findall(r"\b(?:echo|printf)\s+(['\"])(.*?)\1\s*\|\s*(?:sudo\s+)?"
                                       r"(?:(?:ba|z|k|da)?sh|pwsh|powershell|iex)\b", cmd, flags=re.DOTALL | re.I)]
    segs = []
    for p in parts:
        segs += [s.strip() for s in _SPLIT_RE.split(p) if s.strip()]
    return segs


_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\s*(?=\n|$|\))", re.DOTALL)
_MESSAGE_ARG = re.compile(
    r"((?:\s-m|\s--message|\s--body|\s-b|\s--title|\s-t|\s--notes|\s--subject)[= ]\s*)"
    r"(\"(?:[^\"\\\\]|\\\\.)*\"|'[^']*')")
_ECHO_ARGS = re.compile(r"(\b(?:echo|printf|Write-Host|Write-Output|grep|egrep|fgrep|rg|ag|Select-String)\b[^|;&\n]*?)"
                        r"(\"(?:[^\"\\\\]|\\\\.)*\"|'[^']*')")


def neutralize(cmd: str) -> str:
    """Blank out text that is data, not commands: heredoc bodies, commit/PR
    messages, and echo/grep arguments, so `git commit -m "fix rm -rf bug"`
    or `grep "DROP TABLE" src/` don't read as the commands they mention.
    Output piped into a shell is left intact.
    """
    out = _HEREDOC.sub("<<HEREDOC", cmd)
    out = _MESSAGE_ARG.sub(lambda m: m.group(1) + '""', out)
    if not re.search(r"\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b|\|\s*(?:iex|Invoke-Expression|python\d?|node|pwsh)\b", cmd, re.I):
        prev = None
        while prev != out:
            prev, out = out, _ECHO_ARGS.sub(lambda m: m.group(1) + '""', out, count=1)
    return out


def tokenize(segment: str) -> List[str]:
    """Split on whitespace honouring quotes; never raises.

    Non-POSIX mode keeps backslashes intact so Windows paths survive; the
    surrounding quotes are stripped afterwards.
    """
    try:
        lex = shlex.shlex(segment, posix=False, punctuation_chars="<>")
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        toks = segment.split()
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"" else t for t in toks]


def strip_env_prefix(tokens: List[str]) -> List[str]:
    """Drop leading VAR=value assignments and sudo/env/command wrappers."""
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            i += 1
        elif t in ("sudo", "doas", "env", "command", "exec", "nohup", "time", "nice", "xargs"):
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
        else:
            break
    return tokens[i:]


def program_name(tokens: List[str]) -> str:
    if not tokens:
        return ""
    name = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


# --------------------------------------------------------------------- text

def iter_strings(obj: Any, limit: int = 2_000_000) -> Iterator[str]:
    """Yield every string leaf in a JSON-ish object, up to a byte budget."""
    budget = [limit]

    def walk(o):
        if budget[0] <= 0:
            return
        if isinstance(o, str):
            budget[0] -= len(o)
            yield o
        elif isinstance(o, dict):
            for v in o.values():
                yield from walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                yield from walk(v)

    yield from walk(obj)


def flatten_text(obj: Any, limit: int = 2_000_000) -> str:
    return "\n".join(iter_strings(obj, limit))


def map_strings(obj: Any, fn) -> Any:
    """Return a copy of obj with fn applied to every string leaf (shape kept)."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: map_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [map_strings(v, fn) for v in obj]
    return obj


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def redact(value: str, keep: int = 4) -> str:
    """Enough to recognise a value, never enough to use it."""
    v = value.strip()
    if len(v) <= keep + 2:
        return "*" * len(v)
    return "%s…[%d chars]" % (v[:keep], len(v))


def truncate(s: str, n: int = 160) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def json_size(obj: Any) -> int:
    try:
        return len(json.dumps(obj, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return len(str(obj))


def est_tokens(chars: int) -> int:
    """Rough chars→tokens for English/code mixes. Labelled as an estimate."""
    return int(math.ceil(chars / 3.8))
