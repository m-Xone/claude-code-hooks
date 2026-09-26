"""Per-session state shared between concurrent hook processes.

Claude Code runs hooks for parallel tool calls in parallel, so every
read-modify-write goes through a lock. The lock is a directory created with
os.mkdir, which is atomic on every OS and filesystem we care about; fcntl
and msvcrt are avoided so the same code runs everywhere.
"""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator

from . import util

LOCK_STALE_SECONDS = 3.0   # holders keep a lock for milliseconds
LOCK_WAIT_SECONDS = 4.0


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name or "unknown")[:128]


def session_dir(session_id: str) -> str:
    d = os.path.join(util.data_dir(), "state", _safe(session_id))
    os.makedirs(d, exist_ok=True)
    return d


def logs_dir() -> str:
    d = os.path.join(util.data_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return d


@contextmanager
def file_lock(path: str) -> Iterator[None]:
    lock = path + ".lock"
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            os.mkdir(lock)
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > LOCK_STALE_SECONDS:
                    # holder crashed. Rename first: only one waiter can win the rename, so two
                    # waiters can't both delete-and-recreate and end up sharing the lock.
                    grave = "%s.stale.%d.%d" % (lock, os.getpid(), time.monotonic_ns())
                    os.rename(lock, grave)
                    os.rmdir(grave)
                    continue
            except OSError:
                continue
            if time.monotonic() > deadline:
                raise TimeoutError("could not acquire %s" % lock)
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            os.rmdir(lock)
        except OSError:
            pass


def _read(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(path: str, data: Dict[str, Any]) -> None:
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, path)  # atomic on POSIX and Windows


class Store:
    """A named JSON document in the session directory."""

    def __init__(self, session_id: str, name: str):
        self.path = os.path.join(session_dir(session_id), _safe(name) + ".json")

    def read(self) -> Dict[str, Any]:
        return _read(self.path)

    @contextmanager
    def update(self) -> Iterator[Dict[str, Any]]:
        with file_lock(self.path):
            data = _read(self.path)
            yield data
            _write(self.path, data)


def append_jsonl(path: str, record: Dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    with file_lock(path):
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)


def read_jsonl(path: str) -> Iterator[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def audit(event: Dict[str, Any], check: str, action: str, detail: str, **extra: Any) -> None:
    """Append-only audit trail. Callers must pass already-redacted detail."""
    rec = {
        "ts": round(time.time(), 3),
        "session": event.get("session_id"),
        "event": event.get("hook_event_name"),
        "tool": event.get("tool_name"),
        "agent": event.get("agent_type") or None,
        "check": check,
        "action": action,
        "detail": detail,
    }
    rec.update(extra)
    try:
        append_jsonl(os.path.join(logs_dir(), "audit.jsonl"), rec)
    except OSError:
        pass


def prune_sessions(days: float, keep: str = "", now: float = 0.0) -> int:
    """Delete session folders whose newest file is older than `days`. 0 disables.

    Runs at most once a day (marker file), skips the current session, and never raises.
    Returns the number of folders removed.
    """
    import shutil
    if not days or days <= 0:
        return 0
    now = now or time.time()
    root = os.path.join(util.data_dir(), "state")
    marker = os.path.join(root, ".last-prune")
    try:
        if now - os.path.getmtime(marker) < 86400:
            return 0
    except OSError:
        pass
    removed = 0
    cutoff = now - days * 86400
    try:
        names = os.listdir(root)
    except OSError:
        return 0
    for name in names:
        d = os.path.join(root, name)
        if name.startswith(".") or name == _safe(keep) or not os.path.isdir(d):
            continue
        try:
            newest = max([os.path.getmtime(d)] + [os.path.getmtime(os.path.join(d, f)) for f in os.listdir(d)])
            if newest < cutoff:
                shutil.rmtree(d)
                removed += 1
        except OSError:
            continue
    try:
        os.makedirs(root, exist_ok=True)
        with open(marker, "w") as f:
            f.write(str(now))
    except OSError:
        pass
    return removed


def fail_open_flag() -> str:
    """Presence of this file makes an internal crash fail open instead of closed."""
    return os.path.join(util.data_dir(), "FAIL_OPEN")
