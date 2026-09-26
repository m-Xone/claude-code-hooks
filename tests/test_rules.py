import json
import os
import unittest

from helpers import GITHUB_TOKEN, HookTest

from cchooks import rulelab, rules


def rule(**kw):
    base = {"id": "r1", "event": "PreToolUse", "action": "ask", "message": "custom", "mode": "enforce",
            "when": [{"field": "command", "words": ["kubectl"]}]}
    base.update(kw)
    return base


class Parsing(unittest.TestCase):
    def bad(self, data, fragment, origin="user"):
        with self.assertRaises(rules.RuleError) as cm:
            rules.parse(data, origin=origin)
        self.assertIn(fragment, str(cm.exception))

    def test_valid_defaults(self):
        r = rules.parse({k: v for k, v in rule().items() if k != "mode"})
        self.assertEqual((r.mode, r.override, r.label), ("warn", True, "rule:r1"))

    def test_rejections(self):
        self.bad(rule(allow=True), "unknown key")
        self.bad(rule(id="Bad Id"), "id must be")
        self.bad(rule(action="allow"), "action for PreToolUse")
        self.bad(rule(event="UserPromptSubmit", action="block"), "field for UserPromptSubmit")
        self.bad(rule(message=" "), "message is required")
        self.bad(rule(when=[{"field": "command", "words": ["x"], "not": True}]), "at least one condition")
        self.bad(rule(when=[{"field": "command", "words": ["x"], "regex": "x"}]), "exactly one of")
        self.bad(rule(when=[{"field": "command", "glob": ["**/x"]}]), "glob only works on the path")
        self.bad(rule(when=[{"field": "command", "regex": "(a+)+$"}]), "nested quantifier")
        self.bad(rule(when=[{"field": "command", "regex": r"^(\w+\s?)+$"}]), "nested quantifier")
        self.bad(rule(when=[{"field": "command", "regex": "x.*.*y"}]), "quadratic")
        self.bad(rule(when=[{"field": "command", "regex": "("}]), "invalid regex")
        self.bad(rule(when=[{"field": "command", "regex": "prod"}]), "cannot use regex", origin="project")
        self.bad(rule(event="PostToolUse", action="redact", when=[{"field": "command", "words": ["x"]}]),
                 "redact needs")
        self.bad(rule(event="Stop", action="block", tools=["Bash"], when=[{"field": "message", "words": ["x"]}]),
                 "tools only applies")

    def test_regex_risk_allows_ordinary_patterns(self):
        for p in (r"\bMRN[:# ]?\d{6,10}\b", r"--context[= ]prod", r"(?:foo|bar)+", r"\d{3}-\d{2}-\d{4}"):
            self.assertIsNone(rules.regex_risk(p), p)


class CustomRules(HookTest):
    def add(self, data, where=None):
        where = where or os.path.join(self.home, "rules")
        os.makedirs(where, exist_ok=True)
        with open(os.path.join(where, data["id"] + ".json"), "w") as f:
            json.dump(data, f)

    def test_prompt_block_warn_and_override(self):
        self.add(rule(id="mrn", event="UserPromptSubmit", action="block", message="Looks like a medical record number.",
                      when=[{"field": "prompt", "regex": r"\bMRN[:# ]?\d{6,10}\b"}]))
        out, code, err = self.run_event("UserPromptSubmit", prompt="patient MRN 12345678 has a rash")
        self.assertEqual((out.get("decision"), code), ("block", 2))
        self.assertIn("medical record number", out["reason"])
        self.assertIn("rule:mrn", out["reason"])
        out, code, _ = self.run_event("UserPromptSubmit", prompt="document the MRN format")
        self.assertEqual((out, code), ({}, 0))
        out, code, _ = self.run_event("UserPromptSubmit", prompt="MRN 12345678 [[allow-sensitive]]")
        self.assertNotIn("decision", out)
        self.assertIn("override", out["systemMessage"])

    def test_new_rules_default_to_warn(self):
        r = rule(id="w")
        del r["mode"]
        self.add(r)
        out, code, _ = self.bash("kubectl get pods")
        self.assertIsNone(self.decision(out))
        self.assertIn("[warn mode] rule:w would have asked about", out["systemMessage"])

    def test_check_mode_caps_rules(self):
        self.add(rule())
        self.write_config({"custom_rules": {"mode": "warn"}})
        out, _, _ = self.bash("kubectl get pods")
        self.assertIsNone(self.decision(out))
        self.assertIn("warn mode", out["systemMessage"])

    def test_all_conditions_and_negation(self):
        self.add(rule(id="prod-kubectl", message="kubectl against prod.", tools=["Bash", "PowerShell"], when=[
            {"field": "command", "words": ["kubectl"]},
            {"field": "command", "regex": "--context[= ]prod"},
            {"field": "command", "words": ["--dry-run"], "not": True}]))
        self.assertDecision(self.bash("kubectl --context=prod delete pod x"), "ask")
        self.assertDecision(self.bash("kubectl --context=prod delete pod x --dry-run"), None)
        self.assertDecision(self.bash("kubectl --context=staging delete pod x"), None)
        self.assertDecision(self.pre("Write", file_path=os.path.join(self.project, "k.sh"),
                                     content="kubectl --context=prod delete pod x"), None)  # tools filter

    def test_path_glob_on_file_tools_and_shell(self):
        self.add(rule(id="no-prod", action="deny", message="Nothing under deploy/prod.",
                      when=[{"field": "path", "glob": ["**/deploy/prod/**"]}]))
        target = os.path.join(self.project, "deploy", "prod", "values.yaml")
        self.assertDecision(self.pre("Edit", file_path=target, old_string="a", new_string="b"), "deny")
        self.assertDecision(self.bash("cat deploy/prod/values.yaml"), "deny")
        self.assertDecision(self.bash("cat deploy/staging/values.yaml"), None)

    def test_content_and_context(self):
        self.add(rule(id="no-print", action="context", message="Use the logger, not print().",
                      when=[{"field": "content", "regex": r"\bprint\("}]))
        out, _, _ = self.pre("Edit", file_path=os.path.join(self.project, "a.py"), old_string="x",
                             new_string="print(x)")
        self.assertIsNone(self.decision(out))
        self.assertIn("Use the logger", out["hookSpecificOutput"]["additionalContext"])

    def test_mcp_input_with_tool_glob(self):
        self.add(rule(id="no-public-channel", action="deny", message="Don't post to #general.", tools=["mcp__slack__*"],
                      when=[{"field": "input", "words": ["#general"]}]))
        self.assertDecision(self.pre("mcp__slack__post_message", channel="#general", text="hi"), "deny")
        self.assertDecision(self.pre("mcp__slack__post_message", channel="#eng", text="hi"), None)
        self.assertDecision(self.pre("mcp__jira__create", channel="#general"), None)

    def test_redact_output_chains_with_builtin_redaction(self):
        self.add(rule(id="emp-id", event="PostToolUse", action="redact", message="employee IDs",
                      when=[{"field": "output", "regex": r"\bEMP-\d{6}\b"}]))
        out, _, _ = self.run_event("PostToolUse", tool_name="Bash", tool_input={"command": "cat staff.csv"},
                                   tool_response={"stdout": "EMP-123456,alice,%s" % GITHUB_TOKEN, "stderr": ""})
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(new), {"stdout", "stderr"})
        self.assertNotIn("EMP-123456", new["stdout"])
        self.assertNotIn(GITHUB_TOKEN, new["stdout"])       # the built-in redaction survived too
        self.assertIn("[REDACTED:emp-id]", new["stdout"])

    def test_stop_block_and_loop_guard(self):
        self.add(rule(id="no-todo", event="Stop", action="block", message="Finish the TODOs before stopping.",
                      when=[{"field": "message", "words": ["TODO"], "case_sensitive": True}]))
        out, _, _ = self.run_event("Stop", last_assistant_message="Done, left a TODO in parser.py")
        self.assertEqual(out.get("decision"), "block")
        out, _, _ = self.run_event("Stop", last_assistant_message="left a TODO", stop_hook_active=True)
        self.assertNotIn("decision", out)
        out, _, _ = self.run_event("Stop", last_assistant_message="nothing todo here")
        self.assertNotIn("decision", out)

    def test_detector_condition(self):
        self.add(rule(id="pii-to-web", action="deny", message="No personal data to external sites.",
                      tools=["WebFetch"], when=[{"field": "url", "detector": "pii"}]))
        self.assertDecision(self.pre("WebFetch", url="https://x.io/?ssn=123-45-" + "6789", prompt="p"), "deny")
        self.assertDecision(self.pre("WebFetch", url="https://x.io/docs", prompt="p"), None)

    def test_invalid_file_reported_and_others_still_run(self):
        self.add(rule())
        os.makedirs(os.path.join(self.home, "rules"), exist_ok=True)
        with open(os.path.join(self.home, "rules", "broken.json"), "w") as f:
            f.write("{nope")
        out, _, _ = self.run_event("SessionStart", source="startup")
        self.assertIn("1 custom rule file(s) ignored", out["systemMessage"])
        self.assertIn("broken.json", out["systemMessage"])
        self.assertDecision(self.bash("kubectl get pods"), "ask")

    def test_project_rules(self):
        pdir = os.path.join(self.project, ".claude", "cchooks-rules")
        self.add(rule(id="team"), where=pdir)
        self.add(rule(id="sneaky", when=[{"field": "command", "regex": "x"}]), where=pdir)
        out, _, _ = self.bash("kubectl get pods")
        self.assertEqual(self.decision(out), "ask")
        self.assertIn("project-rule:team", out["hookSpecificOutput"]["permissionDecisionReason"])
        out, _, _ = self.run_event("SessionStart", source="startup")
        self.assertIn("cannot use regex", out["systemMessage"])
        self.write_config({"custom_rules": {"project_rules": False}})
        self.assertDecision(self.bash("kubectl get pods"), None)
        # Claude may not add or change rules itself
        self.assertDecision(self.pre("Write", file_path=os.path.join(pdir, "x.json"), content="{}"), "deny")
        self.assertDecision(self.pre("Write", file_path=os.path.join(self.home, "rules", "x.json"), content="{}"),
                            "deny")


class RuleLab(HookTest):
    KUBE = rule(id="prod-kubectl", tools=["Bash"], when=[
        {"field": "command", "words": ["kubectl"]}, {"field": "command", "regex": "--context[= ]prod"}],
        tests={"hit": ["kubectl --context=prod delete pod x"], "miss": ["kubectl --context=dev delete pod x"]})

    def draft(self, data):
        p = os.path.join(self.tmp, data["id"] + ".json")
        with open(p, "w") as f:
            json.dump(data, f)
        return p

    def test_examples(self):
        r = rules.parse(dict(self.KUBE, tests={"hit": ["kubectl --context=prod get x", "kubectl get x"],
                                                "miss": ["kubectl --context prod get x"]}))
        self.assertEqual([ok for _, _, ok in rulelab.run_tests(r, self.project)], [True, False, False])

    def test_samples_fit_the_field(self):
        r = rules.parse(rule(when=[{"field": "path", "glob": ["**/prod/**"]}], tests={"hit": ["deploy/prod/x.yaml"]}))
        self.assertTrue(all(ok for _, _, ok in rulelab.run_tests(r, self.project)))
        r = rules.parse(rule(event="PostToolUse", action="redact", when=[{"field": "output", "words": ["EMP"]}],
                             tests={"hit": ["id EMP here"], "miss": ["EMPTY"]}))
        self.assertTrue(all(ok for _, _, ok in rulelab.run_tests(r, self.project)))

    def test_timing_catches_what_the_heuristic_misses(self):
        r = rules.parse(rule(when=[{"field": "command", "regex": "(a|a)*b"}]))
        self.assertEqual(rulelab.timing_check(r, limit=1.0)[0], "hang")
        self.assertEqual(rulelab.timing_check(rules.parse(self.KUBE))[0], "ok")

    def test_add_mode_remove(self):
        ok, msg = rulelab.add(self.draft(dict(self.KUBE, tests={"hit": ["kubectl get x"]})))
        self.assertFalse(ok)
        self.assertIn("fail", msg)
        ok, path = rulelab.add(self.draft({k: v for k, v in self.KUBE.items() if k != "mode"}))
        self.assertTrue(ok, path)
        with open(path) as f:
            self.assertEqual(json.load(f)["mode"], "warn")        # installed rules default to warn
        self.assertFalse(rulelab.add(self.draft(self.KUBE))[0])  # id taken
        self.assertIn("warn mode", self.bash("kubectl --context=prod delete pod x")[0]["systemMessage"])
        self.assertTrue(rulelab.set_mode("prod-kubectl", "enforce")[0])
        self.assertDecision(self.bash("kubectl --context=prod delete pod x"), "ask")
        self.assertTrue(rulelab.remove("prod-kubectl")[0])
        self.assertDecision(self.bash("kubectl --context=prod delete pod x"), None)

    def test_replay(self):
        tdir = rulelab.transcripts_dir(self.project)
        os.makedirs(tdir)
        lines = [
            {"type": "user", "cwd": self.project, "timestamp": "2026-09-20T10:00:00Z",
             "message": {"role": "user", "content": "use kubectl --context=prod, token " + GITHUB_TOKEN}},
            {"type": "assistant", "cwd": self.project, "timestamp": "2026-09-20T10:00:05Z", "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "kubectl --context=prod get pods"}},
                {"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "kubectl --context=dev get pods"}}]}},
            {"type": "user", "cwd": self.project, "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "pod-1 Running"}]}},
            {"type": "assistant", "cwd": self.project, "message": {"content": [{"type": "text", "text": "Done."}]}},
        ]
        with open(os.path.join(tdir, "s1.jsonl"), "w") as f:
            f.write("\n".join(json.dumps(x) for x in lines) + "\nnot json\n")
        res = rulelab.replay(rules.parse(self.KUBE), self.project)
        self.assertEqual((res["sessions"], res["events"], res["hits"]), (1, 2, 1))
        self.assertIn("kubectl --context=prod get pods", res["examples"][0])
        prompt_rule = rules.parse(rule(event="UserPromptSubmit", action="block",
                                       when=[{"field": "prompt", "words": ["kubectl"]}]))
        res = rulelab.replay(prompt_rule, self.project)
        self.assertEqual(res["hits"], 1)
        self.assertNotIn(GITHUB_TOKEN, res["examples"][0])        # secrets never shown in examples

    def test_rule_changes_need_approval_with_a_summary(self):
        cli = os.path.join(self.home, "lib", "cli.py")
        p = self.draft(self.KUBE)
        out, _, _ = self.bash('python3 -I "%s" rule add %s' % (cli, p))
        self.assertEqual(self.decision(out), "ask")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("install the custom rule 'prod-kubectl'", reason)
        self.assertIn('contains the word "kubectl"', reason)
        self.assertDecision(self.bash('python3 -I "%s" rule mode prod-kubectl enforce' % cli), "ask")
        self.assertDecision(self.bash('python3 -I "%s" rule remove prod-kubectl' % cli), "ask")
        for ro in ("rule test %s" % p, "rule replay %s" % p, "rules", "rule drafts"):
            self.assertDecision(self.bash('python3 -I "%s" %s' % (cli, ro)), None, ro)
        # chaining never rides on the friendly path
        out, _, _ = self.bash('python3 -I "%s" rule add %s; rm -rf %s' % (cli, p, os.path.join(self.home, "rules")))
        self.assertEqual(self.decision(out), "deny")


if __name__ == "__main__":
    unittest.main()
