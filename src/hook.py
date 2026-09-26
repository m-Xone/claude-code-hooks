"""Claude Code hook entry point.

Installed hooks run this in exec form (no shell) as:
    <python> -I <lib>/hook.py <EventName>
with the event JSON on stdin. -I isolates it from PYTHONPATH and user
site-packages, so a repository can't shadow cchooks modules.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GATING_EVENTS = ("PreToolUse", "UserPromptSubmit", "ConfigChange")


def _emit(out, code, err):
    if out:
        sys.stdout.write(json.dumps(out, ensure_ascii=True))
        sys.stdout.flush()
    if err:
        sys.stderr.write(err.encode("ascii", "replace").decode("ascii") + "\n")
    sys.exit(code)


def main():
    arg_event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", "replace")
        event = json.loads(raw) if raw.strip() else {}
        if not isinstance(event, dict):
            event = {}
    except ValueError:
        event = {}
    event.setdefault("hook_event_name", arg_event)
    try:
        from cchooks import engine
        out, code, err = engine.run(event)
    except Exception as e:  # noqa: BLE001 - last line of defence
        name = event.get("hook_event_name", arg_event)
        # this file lives in <claude dir>/cchooks/lib/, which works for custom config folders too
        base = os.environ.get("CCHOOKS_HOME") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fail_open = os.path.exists(os.path.join(base, "FAIL_OPEN"))
        msg = "cchooks crashed (%s: %s)." % (type(e).__name__, e)
        if name in GATING_EVENTS and not fail_open:
            _emit(None, 2, msg + " Failing closed. Run `%s doctor`, or create %s to fail open."
                  % (os.path.join(base, "lib", "cli.py"), os.path.join(base, "FAIL_OPEN")))
        _emit(None, 1, msg)
        return
    _emit(out, code, err)


if __name__ == "__main__":
    main()
