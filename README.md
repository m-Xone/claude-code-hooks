# cchooks

Security and usability hooks for [Claude Code](https://code.claude.com).

- They stop secrets from reaching the model and block destructive commands.
- They defend against prompt injection and stop the agent disabling its own guardrails.
- They show you where your tokens go, cap subagent fan-out, flag AI-sounding prose and catch the agent going in circles.

The hooks are one Python codebase with no dependencies. They behave the same on macOS, Linux and Windows, whichever shell you use.

## Quick start

You need **Python 3.9+** (`python3 --version`, or `py -3 --version` on Windows).

```sh
git clone https://github.com/m-Xone/claude-code-hooks.git && cd claude-code-hooks
sh install.sh --mode warn                                   # macOS / Linux / WSL / Git Bash
```
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 --mode warn   # Windows
```

The installer asks three questions. Press Enter to accept each default:
1. **Claude Code config folder** (`~/.claude`, or `$CLAUDE_CONFIG_DIR` if you use a custom one).
2. **How long to keep per-session data** (30 days; see [Session data](#session-data)).
3. **Which status line to install** (auto; see [Status line](#status-line)). If you already have a status line, it asks before replacing it.

Restart Claude Code. `--mode warn` is a safe way to start: every check tells you what it *would* have blocked but lets everything through. When you're happy with what you see, re-run the installer without `--mode warn` to switch to the normal defaults.

To remove everything again:

```sh
sh install.sh --uninstall        # or: .\install.ps1 --uninstall
```

## What's included

**Security**

| Check | What it does |
|---|---|
| Prompt gate | Holds back a prompt containing API keys, private keys, card numbers, SSNs or IBANs before the model sees it. Emails and phone numbers only get a warning. |
| Sensitive paths | Stops Claude reading `.env` files, SSH keys, cloud credentials, keychains, browser profiles and shell history. This includes attaching one with `@.env` in a prompt. Asks before shell commands that touch them or print environment variables. |
| Destructive commands | Blocks unrecoverable commands, such as deleting `~`, `/` or the project root, or formatting a disk. Asks before force-push, `reset --hard`, `curl \| sh`, `DROP TABLE`, cloud deletes, `sudo` and publishing packages. |
| Secret leaks | Redacts secrets from tool output before Claude reads it. Asks before a secret is written into a file. Blocks commits whose staged changes contain one. |
| Injection tripwire | Spots instructions hidden in web pages, MCP results and downloads, including invisible Unicode. It warns Claude and marks the session *tainted*. |
| Egress guard | Asks before data leaves your machine: uploads, paste sites, webhooks, encoded payloads in URLs. While the session is tainted it asks before any network call. Never lets secrets go out. |
| Tamper guard | Stops Claude editing Claude Code settings or these hooks. Warns if the installed hook files change. |
| Custom rules | Your own checks. `/cchooks-new` builds one with you through a short interview. See [Custom rules](#custom-rules). |

**Usability**

| Check | What it does |
|---|---|
| Cost ledger | Records tokens per model, per subagent and per tool. See it with `/cchooks-report`. |
| Subagent governor | Caps running subagents (default 4 at once, 30 per session). |
| Slop detector | Scores replies and docs for AI writing tells ("Great question!", "delve", "it's not X, it's Y", em-dash overload). |
| Verification gate | Reminds Claude to run tests or lint before finishing a turn in which it edited code. |
| Loop detector | Notices repeated identical calls, re-read files and a run of failing commands, and nudges Claude to change approach. |
| Status line | Shows folder, git branch, model, context use, cost and rate limits, plus a `TAINTED` flag. Fits itself to the terminal width. |

Security checks default to **enforce**. The slop detector and verification gate default to **warn**.

## Everyday use

**A prompt was blocked.** Your prompt was not sent. Remove the secret and resend. If you really do want the model to see it, add `[[allow-sensitive]]` anywhere in the prompt.

**Claude Code asks you about a command.** The prompt starts with `[settings]` and gives the hook's reason. Approve it if it's what you intended.

**"Session marked tainted".** Something Claude read looked like instructions meant for it, so network use now needs your approval. Once you've looked at the source, clear the flag with:

```
! python3 ~/.claude/cchooks/lib/cli.py untaint
```

The `!` prefix makes you the one running it; Claude is blocked from clearing the flag itself. On Windows use `py -3 "$env:USERPROFILE\.claude\cchooks\lib\cli.py" untaint`.

**Where did my tokens go?** Run `/cchooks-report` in Claude Code. The report has two parts:
- *exact* token totals per model and per subagent;
- *estimated* per-tool costs: how much context each tool added, its failure rate and its latency.

**Other commands.** `cli.py` also has `status` (modes, session state, recent audit events), `rules` and `rule` (see [Custom rules](#custom-rules)), `doctor` (health check) and `ruler` (see [Status line](#status-line)).

## Install options

| Option | Effect |
|---|---|
| `--mode warn` / `--mode enforce` | Set every check to warn or enforce. |
| `--hooks-only` | Install just the hooks, even if a starter template is supplied. |
| `--scope project --project DIR` | Register the hooks only in `DIR/.claude/settings.json`. `~/.claude/settings.json` is left alone. |
| `--template DIR` | Deploy a starter `~/.claude` first (see below). |
| `--dry-run` | Show what would change, change nothing. |
| `--retention-days N` | Auto-delete session data after N days unused, or `0` to never auto-delete. Skips the question. |
| `--claude-dir DIR` | Install into a custom Claude Code config folder instead of `~/.claude`. |
| `--statusline auto\|subscription\|api\|none` | Choose the status line without being asked. Choosing one replaces an existing status line; the old one is restored on uninstall. |
| `--statusline-glyphs basic\|ascii\|nerd` | Character set for the status line (default `basic`). |
| `--uninstall [--keep-data]` | Remove the hook entries, `/cchooks-report` and `~/.claude/cchooks/`. `--keep-data` keeps logs and config. |
| `--doctor` | Check the install and run a self-test. |

**What the installer changes.** It backs up `settings.json`, then adds the hook entries and status line to it. Your other settings and hooks are kept. Everything else lives in `<config folder>/cchooks/`. The cloned repo isn't needed after installing.

**Custom config folder.** Claude Code only reads a folder other than `~/.claude` when `CLAUDE_CONFIG_DIR` points to it, so set that in your shell profile too. The installed hooks find their own folder, so they keep working even if the variable isn't passed through.

**Starter templates.** `--template DIR` is for quickstart repos that ship a recommended `~/.claude`.
- `settings.json` is merged: your existing values win, and lists such as permission rules are combined.
- Any other file you already have is saved as `<name>.bak-<timestamp>` before it's replaced.
- Name the template folder something other than `.claude` (for example `claude-home/`). A folder called `.claude` would also act as the repo's own project settings.

## Status line

```
 ~/dev/my-app  main ↑1 +3  Opus 5.5 ·high                    ctx 42% (84.2k / 200k)  $1.23 14m  5h 63% 7d 12%
```

- **Left:** the folder, then the git branch. The branch shows `↑`/`↓` for commits ahead of or behind the remote, `+` for uncommitted changes, and `(local)` if there's no upstream. Then the model and effort level.
- **Right:** context use (blue, then amber at 60%, then magenta at 85%), session cost and duration, and 5-hour / 7-day rate limits.
- **Narrow terminals:** optional pieces are dropped first, then the rest is shortened, so the line never runs off the edge.
- **cchooks extras:** a `TAINTED` flag and the number of running subagents.

Variants:
- `auto` shows the cost and rate-limit meters only when Claude Code sends that data.
- `subscription` is for Pro, Max and Team logins.
- `api` is for API-key logins and shows context only.

Glyph sets:
- `basic` (the default) uses only characters that standard fonts such as Consolas, Cascadia, Menlo and DejaVu all include, so no font changes are needed.
- `ascii` suits old consoles.
- `nerd` adds icons and powerline arrows, but needs a [Nerd Font](https://www.nerdfonts.com). It matches the original bash status line (`statusline.sh`) byte for byte.

Change the variant or glyph set any time in `config.json`:

```json
"statusline": {"variant": "subscription", "glyphs": "basic", "right_reserve": 0, "show_cchooks": true}
```

`show_cchooks: false` hides the `TAINTED` flag and subagent count. The installer sets the status line to refresh every 2 seconds (`refreshInterval` in `settings.json`), so resizing the terminal corrects it quickly.

**If the right end gets cut off:** Claude Code uses a few columns at the right edge for its own badges. To find out how many:
1. Run `cli.py ruler on`. The status line becomes a numbered ruler.
2. Note the last number you can see.
3. Set `right_reserve` to your terminal width minus that number.
4. Run `cli.py ruler off`.

If you used the earlier bash status line, the installer copies your calibrated `RIGHT_RESERVE` from `statusline.conf`.

## Configuration

Paths below assume the default `~/.claude`. If you installed with `--claude-dir`, use that folder instead.


Edit `~/.claude/cchooks/config.json`. Changes apply immediately, with no restart needed. Every check has a `mode` of `off`, `warn` or `enforce`:

```json
{
  "checks": {
    "slop_detector":      {"mode": "enforce", "extra_phrases": ["circle back"]},
    "verification_gate":  {"mode": "enforce"},
    "subagent_governor":  {"max_concurrent": 3},
    "egress_guard":       {"allow_domains": ["internal.example.com"]},
    "destructive_commands": {"extra_rules": [{"pattern": "\\bprod-db\\b", "action": "deny", "reason": "touches prod"}]}
  }
}
```

All settings, with their defaults, are listed in [`src/cchooks/config.py`](src/cchooks/config.py).

A repository can add its own `.claude/cchooks.json`. For security checks it can only make them *stricter*, because you might open a repository you don't trust. Usability settings, such as which test command the verification gate looks for, can be set freely per project.

## Custom rules

Run **`/cchooks-new`** in Claude Code, optionally followed by what you want to catch (`/cchooks-new keep patient record numbers out of prompts`). Claude interviews you with multiple-choice questions. Each option has a preview of what it would look like when the rule fires.

Before the rule is installed, Claude tests it two ways:
- **Examples:** it writes examples the rule should and shouldn't match, and checks the rule gets each one right.
- **History:** it replays the rule against your recent sessions to show how often it would have fired.

Claude Code then asks you to approve the install, and shows a plain-English summary of the rule. **`/cchooks-rules`** lists your rules and switches them between warn, enforce and off, or deletes them.

The same tools work from the command line. Run `cli.py rule` with:
- `test FILE` to check a draft
- `replay FILE` to see how often it would have fired
- `add FILE` to install it
- `mode ID enforce` or `remove ID` to change an installed rule

### Rule format

Each rule is one JSON file in `~/.claude/cchooks/rules/`. It says when to look, what to look for and what to do:

```json
{
  "id": "prod-kubectl",
  "event": "PreToolUse",
  "tools": ["Bash", "PowerShell"],
  "when": [
    {"field": "command", "words": ["kubectl"]},
    {"field": "command", "regex": "--context[= ]prod"},
    {"field": "command", "words": ["--dry-run"], "not": true}
  ],
  "action": "ask",
  "message": "kubectl against the prod cluster.",
  "mode": "warn",
  "tests": {"hit": ["kubectl --context=prod delete pod x"], "miss": ["kubectl --context=prod get pods --dry-run"]}
}
```

All conditions must match. `"not": true` turns a condition into "does not match".

| Event | Fields | Actions |
|---|---|---|
| `UserPromptSubmit` | `prompt` | `block`, `warn`, `context` |
| `PreToolUse` | `command`, `path`, `content`, `url`, `input` | `deny`, `ask`, `warn`, `context` |
| `PostToolUse` | `command`, `path`, `url`, `input`, `output` | `redact`, `warn`, `context` |
| `Stop`, `SubagentStop` | `message` | `block` (Claude keeps working), `warn` |

The fields:
- `path` covers file tools and the paths in shell commands.
- `content` is the text being written by Write or Edit.
- `input` is any argument of any tool, including MCP tools.
- `output` is the tool's result.

Each condition uses one of these match types:
- `words`: a list of whole words.
- `regex`: a regular expression.
- `glob`: path patterns, for the `path` field only.
- `detector`: `secrets`, `pii` or `injection`, which reuse the built-in detectors.

**Other rule settings:**
- **`tools`** restricts a rule to certain tools. Globs such as `mcp__slack__*` work.
- **`message`** is what Claude or you will see when the rule fires.
- **`override`**: a blocked prompt can still be sent with `[[allow-sensitive]]` unless `"override": false`.
- **`tests`**: examples the rule should (`hit`) and shouldn't (`miss`) match. `rule add` refuses a rule whose examples fail.

**Behaviour:**
- **Warn first:** new rules default to `"mode": "warn"`. Switch one to `enforce` once `cli.py rules` and the warnings show it catches what you meant.
- **Stricter only:** rules have no "allow" action, so they can never loosen the built-in checks.
- **Slow regexes:** regexes likely to hang (like `(a+)+`) are refused, and `rule test` times each regex against worst-case input.
- **Claude can't edit them:** the tamper guard stops Claude writing rule files directly. Installing, switching or deleting a rule through `cli.py` needs your approval each time.
- **Invalid files:** a file that doesn't validate is skipped, and you're told at the start of the next session.
- **Project rules:** a repository can ship rules in `.claude/cchooks-rules/`. Because you might open a repository you don't trust, those rules can't use `regex`, and `"project_rules": false` under `custom_rules` in `config.json` turns them off.

## Session data

Each Claude Code session gets a small folder in `~/.claude/cchooks/state/`. It holds the token stats, taint flag, subagent counts and loop history, so each new session starts from zero. Old folders are deleted automatically:
- The installer asks how many days of inactivity to allow before deleting (default 30). `0` means never delete.
- The cleanup runs at most once a day, at session start, and never touches the current session.
- You can change the setting later with `"retention_days"` in `config.json`.

The audit log (`logs/audit.jsonl`) is a permanent record and is never auto-deleted.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Hooks don't seem to run | Restart Claude Code, check `/hooks`, then run `python3 ~/.claude/cchooks/lib/cli.py doctor`. |
| "interpreter no longer exists" | Python was upgraded or moved. Re-run the installer. |
| A check keeps flagging something harmless | Set that check to `warn` in `config.json`, and please open an issue with the command. |
| "cchooks check … failed internally" | If a security check crashes, it asks instead of silently allowing. Run `doctor`. To make crashes allow instead, create `~/.claude/cchooks/FAIL_OPEN`. |

Every block, ask, redaction and warning is logged, with secrets redacted, to `~/.claude/cchooks/logs/audit.jsonl`.

## Limits

These hooks catch mistakes and unsophisticated attacks. A determined attacker can hide a command from pattern matching, for example `$(printf 'r''m') -rf ~`. Use them alongside Claude Code's own protections:
- [permission deny rules](https://code.claude.com/docs/en/permissions)
- the [sandbox](https://code.claude.com/docs/en/sandboxing)

Per-tool token figures are estimates. Per-model and per-subagent totals are exact.

## Development

```sh
cd tests && python3 -m unittest      # 116 tests, including end-to-end installs into temp directories
```

- `src/hook.py` is the hook entry point.
- `src/cli.py` is the command line.
- `src/cchooks/checks/` holds one module per check.
- `src/cchooks/detectors/` holds the shared secret, injection and slop detectors.
- `installer/` contains the installer. `install.sh` and `install.ps1` only locate Python and hand off to it.
- Test credentials are assembled at runtime, so the repo never contains anything a secret scanner would flag.

## License

MIT. See [LICENSE](LICENSE).
