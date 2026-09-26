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

**Usability**

| Check | What it does |
|---|---|
| Cost ledger | Records tokens per model, per subagent and per tool. See it with `/cchooks-report`. |
| Subagent governor | Caps running subagents (default 4 at once, 30 per session). |
| Slop detector | Scores replies and docs for AI writing tells ("Great question!", "delve", "it's not X, it's Y", em-dash overload). |
| Verification gate | Reminds Claude to run tests or lint before finishing a turn in which it edited code. |
| Loop detector | Notices repeated identical calls, re-read files and a run of failing commands, and nudges Claude to change approach. |

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

**Other commands.** `cli.py` also has `status` (modes, session state, recent audit events), `doctor` (health check) and `statusline`.

## Install options

| Option | Effect |
|---|---|
| `--mode warn` / `--mode enforce` | Set every check to warn or enforce. |
| `--hooks-only` | Install just the hooks, even if a starter template is supplied. |
| `--scope project --project DIR` | Register the hooks only in `DIR/.claude/settings.json`. `~/.claude/settings.json` is left alone. |
| `--template DIR` | Deploy a starter `~/.claude` first (see below). |
| `--dry-run` | Show what would change, change nothing. |
| `--statusline` | Also install a status line showing context %, cost, top tools and taint state. macOS and Linux only; see the note below for Windows. |
| `--uninstall [--keep-data]` | Remove the hook entries, `/cchooks-report` and `~/.claude/cchooks/`. `--keep-data` keeps logs and config. |
| `--doctor` | Check the install and run a self-test. |

**What the installer changes.** It backs up `~/.claude/settings.json`, then adds hook entries to it, keeping your existing settings and hooks. Everything else lives in `~/.claude/cchooks/`. The cloned repo isn't needed after installing.

**Starter templates.** `--template DIR` is for quickstart repos that ship a recommended `~/.claude`.
- `settings.json` is merged: your existing values win, and lists such as permission rules are combined.
- Any other file you already have is saved as `<name>.bak-<timestamp>` before it's replaced.
- Name the template folder something other than `.claude` (for example `claude-home/`). A folder called `.claude` would also act as the repo's own project settings.

**Windows status line.** Add it to `settings.json` by hand:

```json
"statusLine": {"type": "command", "command": "& 'C:\\Path\\To\\python.exe' -I 'C:\\Users\\you\\.claude\\cchooks\\lib\\cli.py' statusline"}
```

## Configuration

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
cd tests && python3 -m unittest      # 77 tests, including an end-to-end install into a temp directory
```

- `src/hook.py` is the hook entry point.
- `src/cli.py` is the command line.
- `src/cchooks/checks/` holds one module per check.
- `src/cchooks/detectors/` holds the shared secret, injection and slop detectors.
- `installer/` contains the installer. `install.sh` and `install.ps1` only locate Python and hand off to it.
- Test credentials are assembled at runtime, so the repo never contains anything a secret scanner would flag.

## License

MIT. See [LICENSE](LICENSE).
