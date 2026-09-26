"""cchooks command line.

  cli.py report [SESSION_ID|--latest] [--all-sessions]   token/tool usage report
  cli.py status                                          install + current session state
  cli.py untaint [SESSION_ID|--latest]                   clear the injection taint
  cli.py statusline [--variant auto|subscription|api] [--glyphs basic|ascii|nerd]
                                                         status line (reads Claude Code JSON on stdin)
  cli.py ruler [on|off]                                  calibrate the status line's right-edge reserve
  cli.py doctor                                          health check + self-test
  cli.py selftest
  cli.py uninstall [--keep-data]
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cchooks import __version__, state, util  # noqa: E402
from cchooks.checks import cost_ledger  # noqa: E402


def _sessions_by_recency():
    root = os.path.join(util.data_dir(), "state")
    try:
        names = [n for n in os.listdir(root) if n != "cchooks-selftest"]
    except OSError:
        return []
    return sorted(names, key=lambda n: os.path.getmtime(os.path.join(root, n)), reverse=True)


def _pick_session(args):
    explicit = [a for a in args if not a.startswith("-")]
    if explicit:
        return explicit[0]
    cwd = util.norm_path(os.getcwd())
    sessions = _sessions_by_recency()
    for s in sessions:  # prefer the latest session started in this directory
        meta = state.Store(s, "ledger").read().get("meta", {})
        if meta.get("cwd") and util.is_within(cwd, meta["cwd"]):
            return s
    return sessions[0] if sessions else None


def fmt(n):
    n = float(n)
    for unit, div in (("M", 1e6), ("k", 1e3)):
        if n >= div:
            return "%.1f%s" % (n / div, unit)
    return "%d" % n


def report(args):
    session = _pick_session(args)
    if not session:
        print("No cchooks sessions recorded yet.")
        return 1
    d = cost_ledger.store(session).read()
    print("cchooks tool-cost report  session=%s" % session)
    usage = d.get("usage", {})
    main_calls = usage.get("main", {}).get("tool_calls", {})

    # ---- exact API usage
    print("\nAPI usage (exact, from transcripts; main thread is ingested at each Stop)")
    print("  %-28s %10s %10s %12s %12s" % ("scope / model", "input", "output", "cache read", "cache write"))
    grand = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    for scope, data in sorted(usage.items()):
        for model, u in data.get("by_model", {}).items():
            label = ("%s / %s" % (scope.replace("agent:", "agent "), model))[:28]
            print("  %-28s %10s %10s %12s %12s" % (label, fmt(u["input_tokens"]), fmt(u["output_tokens"]),
                                                 fmt(u["cache_read_input_tokens"]),
                                                 fmt(u["cache_creation_input_tokens"])))
            for k in grand:
                grand[k] += u.get(k, 0)
    print("  %-28s %10s %10s %12s %12s" % ("TOTAL", fmt(grand["input_tokens"]), fmt(grand["output_tokens"]),
                                         fmt(grand["cache_read_input_tokens"]),
                                         fmt(grand["cache_creation_input_tokens"])))
    runs = d.get("agent_runs", {})
    if runs:
        print("  subagent runs: " + ", ".join("%s ×%d" % kv for kv in sorted(runs.items(), key=lambda kv: -kv[1])))

    # ---- per-tool estimates
    tools = d.get("tools", {})
    all_chars = sum(t["result_chars"] for scope in tools.values() for t in scope.values()) or 1
    print("\nPer tool (est.: result tokens = context each tool added; gen = output tokens spent writing calls)")
    print("  %-26s %6s %5s %11s %6s %9s %9s" % ("tool", "calls", "fail", "result tok", "share", "gen tok", "avg ms"))
    for scope in sorted(tools, key=lambda s: (s != "main", s)):
        if scope != "main":
            print("  [subagent: %s]" % scope)
        rows = sorted(tools[scope].items(), key=lambda kv: -kv[1]["result_chars"])
        for name, t in rows:
            gen = main_calls.get(name, {}).get("gen_tokens", 0) if scope == "main" else 0
            print("  %-26s %6d %5d %11s %5.1f%% %9s %9d" % (
                name[:26], t["calls"], t["fails"], fmt(util.est_tokens(t["result_chars"])),
                100.0 * t["result_chars"] / all_chars, fmt(gen) if gen else "-",
                t["ms"] // t["calls"] if t["calls"] else 0))

    # ---- hints
    hints = []
    for scope, rows in tools.items():
        for name, t in rows.items():
            if t["calls"] >= 5 and t["fails"] / t["calls"] > 0.3:
                hints.append("%s fails %.0f%% of the time%s" % (name, 100 * t["fails"] / t["calls"],
                                                              "" if scope == "main" else " in %s" % scope))
            if t["result_chars"] / all_chars > 0.4 and all_chars > 200_000:
                hints.append("%s produced %.0f%% of all tool output: narrow its scope (offset/limit, head, "
                             "files_with_matches)" % (name, 100 * t["result_chars"] / all_chars))
    if hints:
        print("\nWorth a look:")
        for h in hints:
            print("  - " + h)
    return 0


def statusline(args):
    """Status line for Claude Code. Options: --variant auto|subscription|api, --glyphs basic|ascii|nerd."""
    from cchooks import config, statusline as sl
    try:
        cfg = config.load("")
    except config.ConfigError:
        cfg = json.loads(json.dumps(config.DEFAULTS))  # broken config.json: still show a status line
    cfg.setdefault("statusline", {})
    for flag in ("--variant", "--glyphs"):
        if flag in args and args.index(flag) + 1 < len(args):
            cfg["statusline"][flag[2:]] = args[args.index(flag) + 1]

    def extras(data):
        sid = data.get("session_id")
        if not sid:
            return {}
        gov = state.Store(sid, "governor").read()
        return {"tainted": bool(state.Store(sid, "taint").read()),
                "agents": len(gov.get("running", {})) + len(gov.get("pending", {}))}

    return sl.main(cfg, extras)


def ruler(args):
    """Toggle the calibration ruler: the status line prints a numbered ruler instead."""
    from cchooks import statusline as sl
    flag = sl.ruler_flag()
    if args and args[0] == "off":
        if os.path.exists(flag):
            os.remove(flag)
        print("Ruler off.")
    else:
        open(flag, "w").close()
        print("Ruler on. Read the last number fully visible in the status line, then set\n"
              "  \"statusline\": {\"right_reserve\": <terminal width - that number>}\n"
              "in %s, and run `cli.py ruler off`." % os.path.join(util.data_dir(), "config.json"))
    return 0


def untaint(args):
    session = _pick_session(args)
    if not session:
        print("No session found.")
        return 1
    store = state.Store(session, "taint")
    d = store.read()
    if not d:
        print("Session %s is not tainted." % session)
        return 0
    for s in d.get("sources", []):
        print("  was tainted by %s: %s (%s)" % (s.get("tool"), s.get("source"), s.get("signals")))
    os.remove(store.path)
    state.audit({"session_id": session, "hook_event_name": "cli"}, "injection_tripwire", "untaint", "cleared by user")
    print("Cleared taint for session %s." % session)
    return 0


def status(args):
    from cchooks import config
    try:
        with open(os.path.join(util.data_dir(), "install.json"), "r", encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, ValueError):
        info = {}
    print("cchooks %s  (installed: %s)" % (__version__, "yes" if info else "no"))
    if info:
        print("  python   : %s" % info.get("python"))
        print("  settings : %s" % info.get("settings_path"))
    cfg = config.load(util.norm_path(os.getcwd()))
    print("  modes    : " + ", ".join("%s=%s" % (k, config.mode_of(cfg, k)) for k in cfg["checks"]))
    session = _pick_session(args)
    if session:
        taint = state.Store(session, "taint").read()
        gov = state.Store(session, "governor").read()
        print("  session  : %s" % session)
        print("  tainted  : %s" % ("YES (%d sources)" % len(taint.get("sources", [])) if taint else "no"))
        print("  subagents: %d running, %d total this session" % (len(gov.get("running", {})), gov.get("total", 0)))
    recent = list(state.read_jsonl(os.path.join(state.logs_dir(), "audit.jsonl")))[-8:]
    if recent:
        print("  recent audit events:")
        for r in recent:
            print("    %s %-20s %-8s %s" % (time.strftime("%m-%d %H:%M", time.localtime(r.get("ts", 0))),
                                           r.get("check"), r.get("action"), util.truncate(str(r.get("detail")), 70)))
    return 0


def main(argv):
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    if cmd == "report":
        return report(args)
    if cmd == "statusline":
        return statusline(args)
    if cmd == "ruler":
        return ruler(args)
    if cmd == "untaint":
        return untaint(args)
    if cmd == "status":
        return status(args)
    from cchooks import installer
    if cmd == "doctor":
        return installer.doctor()
    if cmd == "selftest":
        return 0 if installer.selftest(verbose=True) else 1
    if cmd == "uninstall":
        return installer.uninstall(keep_data="--keep-data" in args)
    print(__doc__)
    return 0 if cmd in ("-h", "--help", "help") else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
