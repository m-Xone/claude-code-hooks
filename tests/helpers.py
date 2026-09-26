"""Test helpers. Fake credentials are assembled at runtime from pieces so
this repository never contains a literal that secret scanners (or cchooks
itself) would flag."""

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from cchooks import engine  # noqa: E402


def fake(prefix, body_char="Q", n=36, alphabet="Q7mZ2xK9pL"):
    """A syntactically valid, obviously fake token."""
    return prefix + "".join(alphabet[i % len(alphabet)] for i in range(n))


GITHUB_TOKEN = fake("gh" + "p_", n=36)
AWS_KEY_ID = "AK" + "IA" + "Z7Q2M9X4K7P3L8N6"
ANTHROPIC_KEY = fake("sk-" + "ant-api03-", n=90)
PRIVATE_KEY = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
SLACK_TOKEN = "xo" + "xb-" + "1234567890-0987654321-" + fake("", n=24)
JWT = "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
VISA_TEST = "4111 1111 1111 1111"
SSN = "123-45-" + "6789"


class HookTest(unittest.TestCase):
    """Runs the engine in-process against an isolated CCHOOKS_HOME."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cchooks-test-")
        self.home = os.path.join(self.tmp, "cchooks")
        self.project = os.path.join(self.tmp, "project")
        os.makedirs(self.project)
        self._env = {k: os.environ.get(k) for k in ("CCHOOKS_HOME", "CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR")}
        os.environ["CCHOOKS_HOME"] = self.home
        os.environ["CLAUDE_PROJECT_DIR"] = self.project
        os.environ["CLAUDE_CONFIG_DIR"] = os.path.join(self.tmp, "claude")
        self.session = "test-%s" % self.id().rsplit(".", 1)[-1]

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_config(self, checks):
        import json
        os.makedirs(self.home, exist_ok=True)
        with open(os.path.join(self.home, "config.json"), "w") as f:
            json.dump({"checks": checks}, f)

    def run_event(self, name, **fields):
        event = {"hook_event_name": name, "session_id": self.session, "cwd": self.project,
                 "transcript_path": "", "tool_use_id": fields.pop("tool_use_id", "toolu_%d" % id(fields))}
        event.update(fields)
        out, code, err = engine.run(event)
        return out or {}, code, err

    def pre(self, tool, **tool_input):
        return self.run_event("PreToolUse", tool_name=tool, tool_input=tool_input)

    def bash(self, command):
        return self.pre("Bash", command=command)

    @staticmethod
    def decision(out):
        return (out.get("hookSpecificOutput") or {}).get("permissionDecision")

    def assertDecision(self, result, expected, msg=None):
        out, code, _ = result
        got = self.decision(out)
        self.assertEqual(got, expected, msg or "expected %s, got %s: %s" % (expected, got, out))
        self.assertEqual(code, 0)  # PreToolUse decisions travel in JSON; exit 2 is reserved for crashes
