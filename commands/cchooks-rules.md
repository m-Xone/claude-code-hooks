---
description: List, test and switch your custom cchooks rules on or off
---

Every question to the user here is a call to the **AskUserQuestion tool** (1–4 questions, 2–4 options each, header ≤12 characters; "Other" is added automatically). Never type the options into a message and ask the user to reply; fall back to that only if the tool call returns an error.

Run this and show the user its output as a compact table (id, mode, event, action, description). Mention any INVALID lines with the reason.

```
{{CLI}} rules
```

If there are no rules, say so and suggest `/cchooks-new`. Otherwise make one AskUserQuestion tool call with two questions:

1. **"Rule"** (header "Rule"): up to 4 installed rules as options (the rest reachable via Other), each with a `preview` showing the output of `{{CLI}} rule show <id>` — run that for each first.
2. **"Change"** (header "Change"): "Enforce it", "Warn only", "Turn off", "Delete". Put the most likely change first: "Enforce it" for a warn-mode rule, "Warn only" for an enforced one. Each preview says in one line what the user will see afterwards.

Then run the matching command on its own (Claude Code asks the user to approve it):

```
{{CLI}} rule mode <id> enforce|warn|off
{{CLI}} rule remove <id>
```

Before switching a rule to enforce, run `{{CLI}} rule replay <id>` and mention how often it would have fired recently, so the user knows what to expect. Finish with one line confirming the change.
