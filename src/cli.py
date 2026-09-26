"""cchooks command line.

  cli.py report [SESSION_ID|--latest] [--all-sessions]   token/tool usage report
  cli.py status                                          install + current session state
  cli.py untaint [SESSION_ID|--latest]                   clear the injection taint
  cli.py statusline [--variant auto|subscription|api] [--glyphs basic|ascii|nerd]
                                                         status line (reads Claude Code JSON on stdin)
  cli.py ruler [on|off]                                  calibrate the status line's right-edge reserve
  cli.py rules [PROJECT_DIR]                             list custom rules and report invalid ones
  cli.py rule test FILE|ID                               validate a rule, run its examples, time its regexes
  cli.py rule replay FILE|ID [--sessions N] [--all-projects] [--project DIR]
                                                         how often it would have fired in past sessions
  cli.py rule show ID                                    print an installed rule
  cli.py rule add FILE [--replace]                       install a draft (tests must pass)
  cli.py rule mode ID off|warn|enforce                   change an installed rule's mode
  cli.py rule remove ID                                  delete an installed rule
  cli.py rule drafts                                     print the drafts folder the wizard uses
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


def rules(args):
    from cchooks import rules as rules_mod
    project = args[0] if args else os.getcwd()
    total_problems = 0
    for origin, path in (("user", rules_mod.user_rules_dir()), ("project", rules_mod.project_rules_dir(project))):
        found, problems = rules_mod.load_dir(path, origin)
        total_problems += len(problems)
        print("%s rules (%s): %d" % (origin, path, len(found)))
        for r in found:
            tools = " [%s]" % ",".join(r.tools) if r.tools else ""
            print("  %-24s %-7s %-16s %-6s %s" % (r.id, r.mode, r.event + tools, r.action,
                                                  util.truncate(r.description or r.message, 60)))
        for p in problems:
            print("  INVALID %s" % p)
    return 1 if total_problems else 0


def _fmt_sample(sample):
    text = sample if isinstance(sample, str) else json.dumps(sample, ensure_ascii=False)
    return util.truncate(text.replace("\n", " "), 90)


def rule(args):
    from cchooks import rulelab, rules as rules_mod
    if not args:
        print(__doc__)
        return 2
    sub, rest = args[0], args[1:]
    opt = lambda name, default=None: rest[rest.index(name) + 1] if name in rest and rest.index(name) + 1 < len(rest) \
        else default  # noqa: E731
    target = next((a for a in rest if not a.startswith("--")), "")
    if sub == "drafts":
        print(rulelab.drafts_dir())
        return 0
    if sub in ("mode", "remove", "show") and not target:
        print("usage: cli.py rule %s ID%s" % (sub, " off|warn|enforce" if sub == "mode" else ""))
        return 2
    if sub == "mode":
        ok, msg = rulelab.set_mode(target, rest[1] if len(rest) > 1 else "")
        print(("Rule '%s' is now %s (%s). Takes effect on the next event." % (target, rest[1], msg)) if ok else msg)
        return 0 if ok else 1
    if sub == "remove":
        ok, msg = rulelab.remove(target)
        print(("Removed rule '%s' (%s)." % (target, msg)) if ok else msg)
        return 0 if ok else 1
    path = rulelab.find_draft(target) if target else None
    if not path:
        print("No rule file or installed rule called %r." % target)
        return 2
    try:
        r = rulelab.load_file(path)
    except rules_mod.RuleError as e:
        print("INVALID: %s" % e)
        return 2
    if sub == "show":
        with open(path, encoding="utf-8") as f:
            print(f.read().rstrip())
        print("\n" + rules_mod.describe(r))
        return 0
    if sub == "test":
        print("Rule '%s' is valid." % r.id)
        print("  " + rules_mod.describe(r))
        results = rulelab.run_tests(r, os.getcwd())
        if results:
            print("\nExamples:")
            for expect, sample, ok in results:
                note = "" if ok else ("  <- should match but doesn't" if expect == "hit" else "  <- matches but shouldn't")
                print("  %-4s %-4s %s%s" % ("ok" if ok else "FAIL", expect, _fmt_sample(sample), note))
        else:
            print("\nNo examples: add \"tests\": {\"hit\": [...], \"miss\": [...]} to check the rule.")
        verdict, detail = rulelab.timing_check(r)
        print("\nSpeed: %s (%s)" % (verdict, detail))
        passed = sum(1 for t in results if t[2])
        print("Result: %d/%d examples pass%s" % (passed, len(results), "" if verdict == "ok" else ", speed " + verdict))
        return 0 if passed == len(results) and verdict != "hang" else 1
    if sub == "replay":
        try:
            n = int(opt("--sessions", "20"))
        except ValueError:
            n = 20
        res = rulelab.replay(r, opt("--project", os.getcwd()), sessions=n, all_projects="--all-projects" in rest)
        print("Replayed '%s' against %d recent session(s) in %s." % (r.id, res["sessions"], res["where"]))
        print("  %d matching event(s) checked, %d would have fired (in %d session(s)), %.1fs."
              % (res["events"], res["hits"], res["sessions_hit"], res["seconds"]))
        for ex in res["examples"]:
            print("  " + ex)
        if res["sessions"] == 0:
            print("  No past sessions found for this project; try --all-projects.")
        return 0
    if sub == "add":
        ok, msg = rulelab.add(path, replace="--replace" in rest)
        if not ok:
            print(msg)
            return 1
        installed = rulelab.load_file(msg)
        print("Installed rule '%s' in %s mode: %s" % (installed.id, installed.mode, msg))
        print("  " + rules_mod.describe(installed))
        return 0
    print("unknown rule command %r" % sub)
    return 2


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
    if cmd == "rules":
        return rules(args)
    if cmd == "rule":
        return rule(args)
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
