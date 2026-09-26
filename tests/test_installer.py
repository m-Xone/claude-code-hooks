"""End-to-end: install into a throwaway home, run hooks as Claude Code would
(exec form, JSON on stdin), then uninstall."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from helpers import GITHUB_TOKEN, ROOT


class InstallerEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cchooks-e2e-")
        self.env = dict(os.environ, CCHOOKS_HOME=os.path.join(self.tmp, "cchooks"),
                        CLAUDE_CONFIG_DIR=os.path.join(self.tmp, "claude"))
        self.settings = os.path.join(self.tmp, "claude", "settings.json")
        os.makedirs(os.path.dirname(self.settings))
        # pre-existing user config that must survive
        with open(self.settings, "w") as f:
            json.dump({"model": "opus", "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}]}}, f)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def raw(self):
        with open(self.settings) as f:
            return f.read()

    def read(self):
        return json.loads(self.raw())

    def installer(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "installer", "install.py")] + list(args),
                              env=self.env, capture_output=True, text=True, timeout=120)

    def hook(self, event):
        s = self.read()
        h = s["hooks"][event["hook_event_name"]][-1]["hooks"][0]
        r = subprocess.run([h["command"]] + h["args"], input=json.dumps(event), env=self.env,
                           capture_output=True, text=True, timeout=30)
        return r.returncode, json.loads(r.stdout or "{}")

    def test_install_run_uninstall(self):
        r = self.installer()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Self-test passed", r.stdout)

        s = self.read()
        self.assertEqual(s["model"], "opus")
        self.assertEqual(s["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "echo mine")
        ours = s["hooks"]["PreToolUse"][-1]["hooks"][0]
        self.assertTrue(os.path.isabs(ours["command"]))
        self.assertIn("--cchooks", ours["args"])

        # reinstall is idempotent
        self.assertEqual(self.installer().returncode, 0)
        s = self.read()
        self.assertEqual(len(s["hooks"]["PreToolUse"]), 2)

        base = {"session_id": "e2e", "cwd": self.tmp, "transcript_path": ""}
        code, out = self.hook(dict(base, hook_event_name="UserPromptSubmit", prompt="key " + GITHUB_TOKEN))
        self.assertEqual((code, out.get("decision")), (2, "block"))

        # latency budget: PreToolUse runs on every tool call
        t = time.perf_counter()
        for _ in range(5):
            code, out = self.hook(dict(base, hook_event_name="PreToolUse", tool_name="Bash",
                                       tool_input={"command": "ls"}, tool_use_id="x"))
        per_call = (time.perf_counter() - t) / 5
        self.assertEqual(code, 0)
        self.assertLess(per_call, 1.0)
        print("\n  PreToolUse round-trip: %.0f ms" % (per_call * 1000))

        r = self.installer("--doctor")
        self.assertEqual(r.returncode, 0, r.stdout)

        r = self.installer("--uninstall")
        self.assertEqual(r.returncode, 0, r.stdout)
        s = self.read()
        self.assertEqual(s["hooks"], {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "echo mine"}]}]})

    def make_template(self, settings):
        tpl = os.path.join(self.tmp, "claude-home")
        os.makedirs(os.path.join(tpl, "commands"))
        with open(os.path.join(tpl, "settings.json"), "w") as f:
            json.dump(settings, f)
        with open(os.path.join(tpl, "CLAUDE.md"), "w") as f:
            f.write("# Starter instructions\n")
        with open(os.path.join(tpl, "commands", "review.md"), "w") as f:
            f.write("review\n")
        return tpl

    def test_template_merge_and_backup(self):
        claude = os.path.dirname(self.settings)
        with open(self.settings, "w") as f:
            json.dump({"model": "opus", "permissions": {"allow": ["Bash(ls)"]}}, f)
        with open(os.path.join(claude, "CLAUDE.md"), "w") as f:
            f.write("# My own notes\n")
        os.makedirs(os.path.join(claude, "commands"))
        with open(os.path.join(claude, "commands", "review.md"), "w") as f:
            f.write("review\n")  # identical to the template's copy
        tpl = self.make_template({"model": "sonnet", "env": {"FOO": "1"},
                                  "permissions": {"allow": ["Bash(git status)", "Bash(ls)"], "deny": ["Read(./.env)"]}})

        before = self.raw()
        r = self.installer("--template", tpl, "--dry-run")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("back up + replace", r.stdout)
        self.assertEqual(self.raw(), before)  # dry run changed nothing

        r = self.installer("--template", tpl)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        s = self.read()
        self.assertEqual(s["model"], "opus")                      # user's value wins
        self.assertEqual(s["env"], {"FOO": "1"})                  # starter adds new keys
        self.assertEqual(s["permissions"]["allow"], ["Bash(ls)", "Bash(git status)"])  # union, no dupes
        self.assertEqual(s["permissions"]["deny"], ["Read(./.env)"])
        self.assertIn("SessionStart", s["hooks"])
        with open(os.path.join(claude, "CLAUDE.md")) as f:
            self.assertEqual(f.read(), "# Starter instructions\n")
        backups = [n for n in os.listdir(claude) if n.startswith("CLAUDE.md.bak-")]
        self.assertEqual(len(backups), 1)
        with open(os.path.join(claude, backups[0])) as f:
            self.assertEqual(f.read(), "# My own notes\n")
        self.assertEqual([n for n in os.listdir(os.path.join(claude, "commands")) if ".bak-" in n], [])
        self.assertTrue(any(n.startswith("settings.json.bak-") for n in os.listdir(claude)))

    def test_hooks_only_ignores_template_and_uninstall_removes_everything(self):
        claude = os.path.dirname(self.settings)
        tpl = self.make_template({"model": "sonnet"})
        r = self.installer("--hooks-only", "--template", tpl)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(os.path.exists(os.path.join(claude, "CLAUDE.md")))  # template ignored
        self.assertEqual(self.read()["model"], "opus")
        home = self.env["CCHOOKS_HOME"]
        self.assertTrue(os.path.isdir(os.path.join(home, "lib")))
        with open(os.path.join(claude, "commands", "cchooks-new.md")) as f:
            wizard = f.read()
        self.assertNotIn("{{CLI}}", wizard)
        self.assertIn(os.path.join(home, "lib", "cli.py"), wizard)
        r = self.installer("--uninstall")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(os.path.exists(home))
        for name in ("cchooks-report.md", "cchooks-new.md", "cchooks-rules.md"):
            self.assertFalse(os.path.exists(os.path.join(claude, "commands", name)))
        self.assertNotIn("--cchooks", self.raw())
        self.assertEqual(self.read()["model"], "opus")

    def test_template_cannot_disable_hooks(self):
        tpl = self.make_template({"disableAllHooks": True})
        r = self.installer("--template", tpl)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("SessionStart", self.raw())

    def test_retention_flag_and_reinstall_keeps_it(self):
        r = self.installer("--retention-days", "0")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("kept forever", r.stdout)
        cfg = os.path.join(self.env["CCHOOKS_HOME"], "config.json")
        with open(cfg) as f:
            self.assertEqual(json.load(f)["retention_days"], 0)
        r = self.installer()  # non-interactive reinstall keeps the earlier choice
        with open(cfg) as f:
            self.assertEqual(json.load(f)["retention_days"], 0)
        self.assertNotEqual(self.installer("--retention-days", "-3").returncode, 0)

    def test_statusline_keep_replace_restore(self):
        mine = {"type": "command", "command": "~/.claude/statusline.sh", "padding": 0}
        s = self.read()
        s["statusLine"] = mine
        with open(self.settings, "w") as f:
            json.dump(s, f)
        self.assertEqual(self.installer().returncode, 0)        # non-interactive: yours is kept
        self.assertEqual(self.read()["statusLine"], mine)
        r = self.installer("--statusline", "api", "--statusline-glyphs", "ascii")
        self.assertEqual(r.returncode, 0, r.stdout)
        sl = self.read()["statusLine"]
        self.assertIn("cli.py", sl["command"])
        self.assertEqual(sl["refreshInterval"], 2)
        with open(os.path.join(self.env["CCHOOKS_HOME"], "config.json")) as f:
            self.assertEqual(json.load(f)["statusline"], {"variant": "api", "glyphs": "ascii"})
        # the installed command actually runs and prints a line
        out = subprocess.run(sl["command"], shell=True, input=json.dumps(
            {"workspace": {"current_dir": self.tmp}, "model": {"display_name": "M"},
             "context_window": {"used_percentage": 5, "context_window_size": 1000, "total_input_tokens": 50}}),
            capture_output=True, text=True, env=dict(self.env, COLUMNS="100", CLAUDE_PID="999999"))
        self.assertIn("ctx 5%", out.stdout, out.stderr)
        self.assertEqual(self.installer("--uninstall").returncode, 0)
        self.assertEqual(self.read()["statusLine"], mine)          # restored

    def test_statusline_on_fresh_install(self):
        self.assertEqual(self.installer().returncode, 0)
        self.assertIn("cli.py", self.read()["statusLine"]["command"])

    def test_custom_claude_dir(self):
        custom = os.path.join(self.tmp, "my-claude")
        env = dict(self.env)
        env.pop("CCHOOKS_HOME")
        env.pop("CLAUDE_CONFIG_DIR")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "installer", "install.py"), "--claude-dir", custom],
                           env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("CLAUDE_CONFIG_DIR", r.stdout)                 # reminder to export it
        with open(os.path.join(custom, "settings.json")) as f:
            s = json.load(f)
        h = s["hooks"]["PreToolUse"][-1]["hooks"][0]
        self.assertTrue(h["args"][1].startswith(os.path.join(custom, "cchooks", "lib")))
        # run the installed hook with no env hints at all: it must find its own folder
        bare = {k: v for k, v in env.items() if not k.startswith(("CCHOOKS", "CLAUDE_CONFIG"))}
        ev = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": self.tmp, "tool_name": "Edit",
              "tool_input": {"file_path": os.path.join(custom, "settings.json"), "old_string": "a", "new_string": "b"}}
        out = subprocess.run([h["command"]] + h["args"], input=json.dumps(ev), env=bare,
                             capture_output=True, text=True, timeout=30)
        self.assertIn('"deny"', out.stdout)                          # tamper guard knows the custom folder
        self.assertTrue(os.path.isdir(os.path.join(custom, "cchooks", "state", "s1")))
        r = subprocess.run([sys.executable, os.path.join(ROOT, "installer", "install.py"), "--claude-dir", custom,
                            "--uninstall"], env=env, capture_output=True, text=True, timeout=60)
        self.assertFalse(os.path.exists(os.path.join(custom, "cchooks")))

    def test_malformed_settings_aborts(self):
        with open(self.settings, "w") as f:
            f.write("{not json")
        r = self.installer()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.raw(), "{not json")


if __name__ == "__main__":
    unittest.main()
