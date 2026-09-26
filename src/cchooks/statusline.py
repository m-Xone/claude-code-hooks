"""Claude Code status line: identity on the left, meters right-aligned.

A Python port of a hand-tuned bash status line, made to run anywhere
cchooks runs (no bash, jq, awk or stty needed) and to look right in a
stock terminal font.

Variants (what the right-hand meters show):
  subscription  context, session cost + duration, 5h/7d rate limits
  api           context only (API-key sessions get no rate limits, and the
                cost block isn't sent either)
  auto          whichever of those Claude Code actually sends (default)

Glyph sets:
  basic  arrows and dots every system font has (default)
  ascii  pure ASCII, for legacy consoles
  nerd   Nerd Font icons and powerline separators (needs a patched font)

When the line can't fit, optional segments are dropped first, then every
segment switches to its compact form, then segments are dropped by
priority, so nothing ever runs off the edge.

Two host behaviours worth knowing:
  * Claude Code captures stdout, so the terminal size comes from COLUMNS
    (which it exports) or, on macOS/Linux, the live size of Claude Code's tty.
  * A resize doesn't re-run the command; the installer sets refreshInterval
    so a resize corrects itself within a second.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import util

ESC = "\033"

GLYPHS = {
    # Only characters from the WGL4 set, which Consolas, Cascadia, Menlo, Monaco,
    # DejaVu Sans Mono and Liberation Mono all include at a fixed single width.
    "basic": dict(dir="", git="", model="", ctx="ctx ", cost="$", rate="", mode="",
                  ahead="↑", behind="↓", dirty="+", noup=" (local)", fork="wt:", dot="·", fast="»",
                  ellipsis="…", sep="", sepl="", taint="! TAINTED", agents="agents "),
    "ascii": dict(dir="", git="", model="", ctx="ctx ", cost="$", rate="", mode="",
                  ahead="^", behind="v", dirty="+", noup=" (local)", fork="wt:", dot="-", fast=">>",
                  ellipsis="...", sep="", sepl="", taint="! TAINTED", agents="agents "),
    "nerd": dict(dir=" ", git=" ", model=" ", ctx=" ", cost=" ", rate=" ",
                 mode=" ", ahead="", behind="", dirty="", noup=" ", fork="",
                 dot="·", fast="»", ellipsis="…", sep="", sepl="", taint=" TAINTED",
                 agents=" "),
}

# Colour-blind safe: blue nominal, amber attention, magenta critical, and every
# state also carries text, so colour is never the only signal.
C_OK, C_WARN, C_CRIT = 39, 214, 170
GIT_CLEAN = (24, 231)
GIT_DIRTY = (136, 16)
CWD_PALETTE = [17, 18, 19, 22, 23, 24, 25, 26, 27, 52, 53, 54, 55, 56, 58, 59, 60, 61, 62,
               64, 88, 89, 90, 91, 94, 95, 96, 97, 98, 100, 101, 130, 131, 132, 133, 138]


@dataclass
class Seg:
    side: str
    bg: int
    fg: int
    full: str
    compact: str
    prio: int
    on: bool = True

    def text(self, compact: bool) -> str:
        return self.compact if compact and self.compact else self.full


# ------------------------------------------------------------------ helpers

def settings(cfg: Dict[str, Any]) -> Dict[str, Any]:
    s = {"variant": "auto", "glyphs": "basic", "right_reserve": 0, "right_margin": 0, "git_timeout": 2.0,
         "show_cchooks": True}
    s.update(cfg.get("statusline") or {})
    env = os.environ
    for key, var, cast in (("right_reserve", "CC_STATUSLINE_RESERVE", int),
                           ("right_margin", "CC_STATUSLINE_RIGHT_MARGIN", int),
                           ("git_timeout", "CC_STATUSLINE_GIT_TIMEOUT", float),
                           ("glyphs", "CC_STATUSLINE_GLYPHS", str),
                           ("variant", "CC_STATUSLINE_VARIANT", str)):
        if env.get(var):
            try:
                s[key] = cast(env[var])
            except ValueError:
                pass
    if s["glyphs"] not in GLYPHS:
        s["glyphs"] = "basic"
    return s


def short_path(p: str) -> str:
    home = os.path.expanduser("~")
    norm = p.replace("\\", "/")
    h = home.replace("\\", "/")
    if norm.lower() == h.lower():
        return "~"
    if norm.lower().startswith(h.lower() + "/"):
        norm = "~/" + norm[len(h) + 1:]
    parts = [x for x in norm.split("/") if x != ""]
    lead = "/" if norm.startswith("/") else ""
    if len(parts) <= 3:
        return lead + "/".join(parts) if parts else norm
    return "…/%s/%s" % (parts[-2], parts[-1])


def path_color(s: str) -> int:
    h = 0
    for ch in s:  # same hash as the bash original, so colours match across versions
        h = (h * 31 + ord(ch)) % 16777213
    return CWD_PALETTE[h % len(CWD_PALETTE)]


def unit(n: float) -> str:
    if n >= 1_000_000:
        v, u = n / 1_000_000, "m"
    elif n >= 1000:
        v, u = n / 1000, "k"
    else:
        return "%d" % n
    t = "%.1f" % v
    return (t[:-2] if t.endswith(".0") else t) + u


def hms(ms: float) -> str:
    sec = int(ms / 1000)
    if sec < 60:
        return "%ds" % sec
    mins = sec // 60
    if mins < 60:
        return "%dm" % mins
    return "%dh%02dm" % (mins // 60, mins % 60)


def ramp(v: float) -> int:
    return C_CRIT if v >= 85 else (C_WARN if v >= 60 else C_OK)


def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _live_cols() -> int:
    """Width of Claude Code's own tty (macOS/Linux). 0 when unavailable."""
    if util.IS_WINDOWS:
        return 0
    pid = os.environ.get("CLAUDE_PID") or str(os.getppid())
    cache = os.path.join(tempfile.gettempdir(), "cc-statusline-tty.%s" % pid)
    name = ""
    try:
        with open(cache) as f:
            name = f.read().strip()
    except OSError:
        try:
            name = subprocess.run(["ps", "-o", "tty=", "-p", pid], capture_output=True, text=True,
                                  timeout=1).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return 0
        if not re.fullmatch(r"[A-Za-z0-9/]+", name or ""):
            return 0
        try:
            with open(cache, "w") as f:
                f.write(name)
        except OSError:
            pass
    dev = "/dev/" + name
    if not os.path.exists(dev):
        return 0
    try:
        fd = os.open(dev, os.O_RDONLY | getattr(os, "O_NOCTTY", 0))
        try:
            return os.get_terminal_size(fd).columns
        finally:
            os.close(fd)
    except OSError:
        return 0


def term_cols() -> int:
    c = _live_cols()
    if c <= 0:
        try:
            c = int(os.environ.get("COLUMNS", "0"))
        except ValueError:
            c = 0
    return c if c > 0 else 80


def git_info(cwd: str, timeout: float) -> Optional[Tuple[str, str, bool, int, int, int]]:
    """(head, oid7, has_upstream, ahead, behind, dirty) or None outside a repo."""
    try:
        r = subprocess.run(["git", "--no-optional-locks", "status", "--porcelain=v2", "--branch"], cwd=cwd,
                           capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    head, oid, up, ahead, behind, dirty = "-", "-", False, 0, 0, 0
    for line in r.stdout.splitlines():
        if line.startswith("# branch.head "):
            head = line.split(" ", 2)[2]
        elif line.startswith("# branch.oid "):
            oid = line.split(" ", 2)[2][:7]
        elif line.startswith("# branch.upstream "):
            up = True
        elif line.startswith("# branch.ab "):
            _, _, a, b = line.split(" ")[:4]
            ahead, behind = int(a.lstrip("+") or 0), int(b.lstrip("-") or 0)
        elif line[:2] in ("1 ", "2 ", "u ", "? "):
            dirty += 1
    return head, oid, up, ahead, behind, dirty


# ------------------------------------------------------------------- layout

def _measure(segs: List[Seg], compact: bool, sepw: int) -> Tuple[int, int, int, int, int]:
    ml = mr = nl = nr = 0
    for s in segs:
        if not s.on:
            continue
        w = len(s.text(compact)) + 2 + sepw
        if s.side == "L":
            ml, nl = ml + w, nl + 1
        else:
            mr, nr = mr + w, nr + 1
    need = ml + mr + (1 if nl and nr else 0)
    return ml, mr, nl, nr, need


def _drop_weakest(segs: List[Seg], cap: int = 99999) -> bool:
    live = [s for s in segs if s.on]
    if len(live) <= 1:
        return False
    weakest = min(live, key=lambda s: s.prio)
    if weakest.prio > cap:
        return False
    weakest.on = False
    return True


def fit(segs: List[Seg], avail: int, sepw: int, optional_prio: int) -> bool:
    """Mutates segs in place; returns the compact flag to render with."""
    compact = False
    while _measure(segs, compact, sepw)[4] > avail and _drop_weakest(segs, optional_prio):
        pass
    if _measure(segs, compact, sepw)[4] > avail:
        compact = True
    while _measure(segs, compact, sepw)[4] > avail and _drop_weakest(segs):
        pass
    return compact


def render(segs: List[Seg], compact: bool, avail: int, g: Dict[str, str]) -> str:
    sep, sepl = g["sep"], g["sepl"]
    sepw = 1 if sep else 0
    out, prev = [], None
    for s in segs:
        if not (s.on and s.side == "L"):
            continue
        if prev is not None and sep:
            out.append("%s[48;5;%dm%s[38;5;%dm%s" % (ESC, s.bg, ESC, prev, sep))
        else:
            out.append("%s[48;5;%dm" % (ESC, s.bg))
        out.append("%s[38;5;%dm %s " % (ESC, s.fg, s.text(compact)))
        prev = s.bg
    if prev is not None:
        out.append("%s[0m" % ESC + ("%s[38;5;%dm%s%s[0m" % (ESC, prev, sep, ESC) if sep else ""))
    ml, mr, nl, nr, _ = _measure(segs, compact, sepw)
    if nr:
        out.append("%s[0m%s" % (ESC, " " * max(1, avail - ml - mr)))
        prev = None
        for s in segs:
            if not (s.on and s.side == "R"):
                continue
            if sepl:
                if prev is not None:
                    out.append("%s[48;5;%dm%s[38;5;%dm%s" % (ESC, prev, ESC, s.bg, sepl))
                else:
                    out.append("%s[0m%s[38;5;%dm%s" % (ESC, ESC, s.bg, sepl))
            out.append("%s[48;5;%dm%s[38;5;%dm %s " % (ESC, s.bg, ESC, s.fg, s.text(compact)))
            prev = s.bg
        out.append("%s[0m" % ESC)
    return "".join(out)


def ruler(cols: int) -> str:
    buf = ["."] * cols
    for m in range(5, cols + 1, 5):
        lab = str(m)
        buf[m - len(lab):m] = list(lab)
    return "".join(buf)


def ruler_flag() -> str:
    return os.environ.get("CC_STATUSLINE_RULER_FLAG") or os.path.join(tempfile.gettempdir(), "cc-statusline-ruler")


# --------------------------------------------------------------------- build

def build(data: Dict[str, Any], cfg: Dict[str, Any], cols: Optional[int] = None,
          extras: Optional[Dict[str, Any]] = None) -> str:
    s = settings(cfg)
    g = GLYPHS[s["glyphs"]]
    cols = cols or term_cols()
    if os.path.exists(ruler_flag()):
        return ruler(cols)

    ws = data.get("workspace") if isinstance(data.get("workspace"), dict) else {}
    cur = ws.get("current_dir") or data.get("cwd") or os.getcwd()
    model = data.get("model") if isinstance(data.get("model"), dict) else {}
    model_name = model.get("display_name") or model.get("id") or "?"
    effort = (data.get("effort") or {}).get("level", "") if isinstance(data.get("effort"), dict) else ""
    fast = bool(data.get("fast_mode"))
    nothink = isinstance(data.get("thinking"), dict) and data["thinking"].get("enabled") is False
    cw = data.get("context_window") if isinstance(data.get("context_window"), dict) else {}
    ctx_used, ctx_size = _num(cw.get("total_input_tokens")), _num(cw.get("context_window_size"))
    ctx_pct = int(max(0.0, _num(cw.get("used_percentage"))) + 0.5)
    cost_blk = data.get("cost") if isinstance(data.get("cost"), dict) else {}
    cost, dur_ms = _num(cost_blk.get("total_cost_usd")), _num(cost_blk.get("total_duration_ms"))
    rl = data.get("rate_limits") if isinstance(data.get("rate_limits"), dict) else {}
    rl5 = (rl.get("five_hour") or {}).get("used_percentage") if isinstance(rl.get("five_hour"), dict) else None
    rl7 = (rl.get("seven_day") or {}).get("used_percentage") if isinstance(rl.get("seven_day"), dict) else None
    style = (data.get("output_style") or {}).get("name", "") if isinstance(data.get("output_style"), dict) else ""
    vim = (data.get("vim") or {}).get("mode", "") if isinstance(data.get("vim"), dict) else ""
    agent = (data.get("agent") or {}).get("name", "") if isinstance(data.get("agent"), dict) else ""
    worktree = (data.get("worktree") or {}).get("name", "") if isinstance(data.get("worktree"), dict) else ""

    segs: List[Seg] = []

    def add(side, bg, fg, full, comp, prio):
        segs.append(Seg(side, bg, fg, full, comp if comp and len(comp) < len(full) else "", prio))

    # ---- left: where you are, what you're driving
    base = re.split(r"[\\/]", cur.rstrip("\\/"))[-1] or cur
    add("L", path_color(cur), 231, g["dir"] + short_path(cur), g["dir"] + base, 8)

    gi = git_info(cur, float(s["git_timeout"]))
    if gi:
        head, oid, up, ahead, behind, dirty = gi
        branch = "detached@" + oid if head == "(detached)" else head
        detail = ""
        if ahead:
            detail += " %s%d" % (g["ahead"], ahead)
        if behind:
            detail += " %s%d" % (g["behind"], behind)
        if dirty:
            detail += " %s%d" % (g["dirty"], dirty)
        if not up and head != "(detached)":
            detail += g["noup"]
        short_branch = branch if len(branch) <= 14 else branch[:13] + g["ellipsis"]
        bg, fg = GIT_DIRTY if (dirty or ahead or behind) else GIT_CLEAN
        add("L", bg, fg, g["git"] + branch + detail, g["git"] + short_branch + detail, 5)

    model_txt = g["model"] + model_name
    if effort:
        model_txt += " %s%s" % (g["dot"], effort)
    if fast:
        model_txt += " %sfast" % g["fast"]
    if nothink:
        model_txt += " %snothink" % g["dot"]
    add("L", 237, 252, model_txt, g["model"] + model_name.split(" (")[0], 6)

    modes = []
    if style and style.lower() not in ("default", "null"):
        modes.append(style)
    if vim:
        modes.append(vim)
    if agent:
        modes.append("@" + agent)
    if worktree:
        modes.append(g["fork"] + worktree)
    if modes:
        add("L", 239, 250, g["mode"] + " ".join(modes), g["mode"] + modes[0], 2)

    # ---- right: meters, flush to the edge
    variant = s["variant"]
    if ctx_size:
        add("R", 236, ramp(ctx_pct), "%s%d%% (%s / %s)" % (g["ctx"], ctx_pct, unit(ctx_used), unit(ctx_size)),
            "%s%d%%" % (g["ctx"], ctx_pct), 7)
    if variant != "api" and cost > 0:
        c = "%s%.2f" % (g["cost"], cost)
        add("R", 235, 245, "%s %s" % (c, hms(dur_ms)), c, 3)
    if variant != "api" and (rl5 is not None or rl7 is not None):
        full = " ".join(x for x in ("5h %.0f%%" % _num(rl5) if rl5 is not None else "",
                                    "7d %.0f%%" % _num(rl7) if rl7 is not None else "") if x)
        short = "5h %.0f%%" % _num(rl5) if rl5 is not None else full
        worst = max(_num(rl5), _num(rl7))
        add("R", 234, ramp(worst), g["rate"] + full, g["rate"] + short, 1)

    # ---- cchooks state
    extras = extras or {}
    if s["show_cchooks"] and extras.get("agents"):
        add("R", 238, 250, "%s%d" % (g["agents"], extras["agents"]), "", 2)
    if s["show_cchooks"] and extras.get("tainted"):
        add("L", 170, 231, g["taint"], "TAINTED", 9)  # security state outlives everything else
        segs.insert(0, segs.pop())

    avail = cols - int(s["right_reserve"]) - int(s["right_margin"])
    sepw = 1 if g["sep"] else 0
    compact = fit(segs, avail, sepw, optional_prio=3)  # rate limits (1), modes (2), cost (3)
    return render(segs, compact, avail, g)


def main(cfg: Dict[str, Any], extras_fn=None) -> int:
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", "replace")
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            data = {}
    except ValueError:
        data = {}
    try:
        extras = extras_fn(data) if extras_fn else {}
        line = build(data, cfg, extras=extras)
    except Exception:  # noqa: BLE001 - a status line must always print something
        line = short_path(os.getcwd())
    out = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else None
    if out:
        out.write(line.encode("utf-8"))
        out.flush()
    else:
        sys.stdout.write(line)
    return 0
