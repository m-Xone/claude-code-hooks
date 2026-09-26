---
description: Create a custom cchooks rule through a short guided interview
argument-hint: "[what the rule should catch, in plain words]"
---

You are running the **cchooks rule wizard**. Turn what the user wants into one tested custom rule, then install it. The user may not know how hooks work: never ask them to write JSON or regexes, and only ask about what you cannot reasonably infer.

## How to ask questions (required)

Every question to the user in this wizard is a call to the **AskUserQuestion tool**. Never write a question, a numbered list of options, or "reply with your choice" in a normal message: the wizard's point is the clickable question with previews. This holds on every run and every step, including when the answer seems obvious (then recommend it, don't skip the tool).

The tool's limits, so a question always fits:
- 1–4 questions per call; 2–4 options per question (the tool adds "Other" itself, don't add one).
- `header` at most 12 characters; `label` 1–5 words; previews only on single-select questions.
- More than 4 possible answers: offer the 3–4 likeliest and let "Other" cover the rest, or split into two calls.

Only if the AskUserQuestion call itself returns an error (for example in a non-interactive session) may you fall back to a plain numbered list, and say that is why.

The user's starting description (may be empty): $ARGUMENTS

## Commands you use

```
{{CLI}} rule drafts                 # prints the drafts folder (call once, write drafts there)
{{CLI}} rule test <draft.json>      # validates, runs the examples, times the regexes
{{CLI}} rule replay <draft.json>    # how often it would have fired in recent sessions here
{{CLI}} rule add <draft.json>       # installs it; Claude Code asks the user to approve
{{CLI}} rules                       # lists installed rules (check the id is free)
```

Run each exactly as written, on its own, never chained with `&&`, `;` or pipes. Write the draft with the Write tool to `<drafts folder>/<id>.json`. You cannot write to the cchooks folder yourself: that is deliberate.

## Rule format

```json
{
  "id": "short-kebab-id",
  "description": "one line for the rule list",
  "event": "PreToolUse",
  "tools": ["Bash", "PowerShell"],
  "when": [ {"field": "command", "words": ["kubectl"]}, {"field": "command", "words": ["--dry-run"], "not": true} ],
  "action": "ask",
  "message": "What the user or Claude sees when it fires.",
  "mode": "warn",
  "tests": {"hit": ["kubectl delete pod x"], "miss": ["kubectl delete pod x --dry-run", "kubectl-docs.md"]}
}
```

| event | fields | actions |
|---|---|---|
| `UserPromptSubmit` (user sends a prompt) | `prompt` | `block`, `warn`, `context` |
| `PreToolUse` (before a tool runs) | `command`, `path`, `content`, `url`, `input` | `deny`, `ask`, `warn`, `context` |
| `PostToolUse` (after a tool runs) | `command`, `path`, `url`, `input`, `output` | `redact`, `warn`, `context` |
| `Stop` / `SubagentStop` (Claude / a subagent finishes) | `message` | `block` (Claude keeps working), `warn` |

- Fields: `path` = file-tool paths and paths inside shell commands; `content` = text being written by Write/Edit; `input` = any tool argument (use it for MCP tools); `output` = the tool result.
- Each condition has exactly one of: `words` (whole words, case-insensitive unless `"case_sensitive": true`), `regex`, `glob` (path patterns, `path` field only, e.g. `**/deploy/prod/**`), `detector` (`secrets`, `pii` or `injection`). All conditions must match; `"not": true` inverts one.
- `tools` takes names or globs (`mcp__slack__*`). Tool names: Bash, PowerShell, Read, Write, Edit, MultiEdit, Grep, Glob, WebFetch, WebSearch, Agent, NotebookEdit, and `mcp__<server>__<tool>`.
- Messages: for `deny`/`block`/`context` the message goes to Claude, so say what to do instead. For `ask`/`warn` the user reads it.
- Prefer `words` or `glob` over `regex`. If you need a regex, keep it bounded (`\d{6,10}`, not `\d+` inside a repeated group) — nested or adjacent unbounded repeats are rejected.
- Tests: a string sample goes into the first condition's field. For rules that look at two fields, use an event object, e.g. `{"tool_name": "Write", "tool_input": {"file_path": "a.py", "content": "print(1)"}}`. Use obviously fake values (`123-45-6789`, `EMP-000001`), never real data.

## The interview

Start every step's message with a one-line progress header, e.g. `**Rule wizard** · ●●○○○ 2/5 · Test`. Steps: 1 Describe, 2 Shape, 3 Test, 4 Review, 5 Install.

**1 · Describe.** If the starting description above already says what to catch, skip to step 2. Otherwise call the AskUserQuestion tool (header "Goal") with these four options, each with a `preview` showing a finished example rule as a short plain-English card plus the key JSON lines. The user can pick "Other" to describe their own.
- Keep something out of prompts (e.g. patient record numbers, a client or project codename)
- Guard a command, file or folder (e.g. anything touching `deploy/prod/`, `terraform destroy`)
- Scrub tool output (e.g. employee IDs in query results are replaced before Claude reads them)
- Check Claude's replies (e.g. don't stop while "TODO" remains; warn on forbidden terms)

**2 · Shape.** Draft the rule in your head, then make one AskUserQuestion tool call with only the questions you can't settle yourself (at most 3). Every option gets a `preview`; put the option you recommend first with "(Recommended)" in its label.
- **"When"** (only if unclear) — each preview is this timeline with the chosen point marked `◆`:
  ```
  you type ─▶ ◇ prompt check ─▶ Claude works
     ─▶ ◇ before tool ─▶ tool runs ─▶ ◇ after tool
     ─▶ Claude replies ─▶ ◇ reply check
  ```
- **"Action"** (always ask) — each preview is a realistic mock of what happens, built from your draft message, e.g. for `ask`:
  ```
  ● Bash(kubectl --context=prod delete pod api-7f)
  ╭──────────────────────────────────────────────╮
  │ [cchooks:rule:prod-kubectl]                  │
  │ kubectl against the prod cluster.            │
  │ Do you want to proceed?  › Yes   No          │
  ╰──────────────────────────────────────────────╯
  ```
  and for `block` on a prompt: `✗ Prompt not sent — [cchooks:rule:…] Your prompt was NOT sent: <message> Edit it and resend, or add [[allow-sensitive]] …`. For `deny`, show Claude being told no and changing course; for `warn`, a one-line notice with the action going ahead; for `redact`, the output with `[REDACTED:<id>]` in place.
- **"Scope"** (only if the match could be too broad) — options narrowing it (which tools, which folders, exceptions), each preview listing 2–3 things that would and wouldn't match.

**3 · Test.** Write the draft with 3–5 `hit` and 3–5 `miss` examples. The misses should be near-misses that a sloppy rule would catch (the word in a filename, the dry-run variant, documentation that mentions the term). Run `rule test`. If an example fails or speed isn't `ok`, fix the rule (not the examples, unless the example was wrong) and re-run, at most 3 times, before showing the user. Then run `rule replay`. Show both results together in one compact block:
```
Examples  ✓ 8/8      Speed  ok (0.4 ms worst case)
History   would have fired 3× in 2 of your last 20 sessions here
          2026-09-24  Bash  kubectl --context=prod rollout restart api
```
If the replay shows many hits, say whether they look intended; if it would have fired on most sessions, suggest narrowing it before continuing.

**4 · Review.** Call the AskUserQuestion tool (header "Install?") with the preview on the first option showing the `describe` sentence from `rule test`, then the full JSON. Options: "Install in warn mode (Recommended)" — the rule only shows notices until they switch it on; "Install enforcing now"; "Change something". On "Change something", call AskUserQuestion again with the 2–4 likeliest changes (the user can type anything via Other), revise, and go back to step 3.

**5 · Install.** If they chose enforcing, set `"mode": "enforce"` in the draft. Tell the user in one line that Claude Code will now ask them to approve the install, then run `rule add`. Finish with a short summary: the rule id and mode, one sentence on what it does, and how to change it later: `/cchooks-rules` to switch modes or delete it. Don't recap the whole interview.

If the user wants several rules, finish one completely before starting the next.

Reminder: every question above is an AskUserQuestion tool call, never a question typed into your reply.
