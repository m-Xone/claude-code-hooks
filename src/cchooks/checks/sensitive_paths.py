"""2. Sensitive-path guard: keep credential stores out of Claude's context.

Permission deny rules such as Read(.env) don't stop `cat .env` in a shell,
so this check looks at file tools *and* at path-like tokens inside
Bash/PowerShell commands, plus commands that dump the whole environment.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .. import util
from ..engine import Context

NAME = "sensitive_paths"
KIND = "security"

PATTERNS: List[str] = [
    # dotenv and friends
    "**/.env", "**/.env.*", "**/*.env", "**/.envrc", "**/.dev.vars",
    # keys and keystores
    "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore", "**/*.ppk",
    "**/id_rsa", "**/id_dsa", "**/id_ecdsa", "**/id_ed25519", "**/id_ecdsa_sk", "**/id_ed25519_sk",
    "~/.ssh/**", "~/.gnupg/**",
    # cloud and tool credentials
    "~/.aws/credentials", "~/.aws/sso/cache/**", "~/.aws/cli/cache/**",
    "~/.config/gcloud/**", "~/AppData/Roaming/gcloud/**",
    "~/.azure/**", "~/.kube/config", "~/.docker/config.json", "~/.netrc", "~/_netrc",
    "~/.npmrc", "~/.pypirc", "~/.git-credentials", "~/.config/gh/hosts.yml",
    "~/.bash_history", "~/.zsh_history", "~/.python_history", "~/.node_repl_history", "~/.psql_history",
    "~/.mysql_history", "~/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/*_history.txt",
    "~/.local/share/fish/fish_history",
    "~/.terraform.d/credentials.tfrc.json", "~/.vault-token", "~/.claude/.credentials.json",
    "**/credentials.json", "**/service-account*.json", "**/*-sa-key.json",
    "**/*.tfstate", "**/*.tfstate.backup", "**/terraform.tfvars", "**/secrets.y*ml", "**/secrets.json",
    # OS keychains and browser profiles (cookies, saved passwords)
    "~/Library/Keychains/**", "~/Library/Cookies/**",
    "~/Library/Application Support/Google/Chrome/**", "~/Library/Application Support/Firefox/**",
    "~/Library/Application Support/Microsoft Edge/**", "~/Library/Application Support/BraveSoftware/**",
    "~/.config/google-chrome/**", "~/.config/chromium/**", "~/.mozilla/firefox/**",
    "~/AppData/Local/Google/Chrome/User Data/**", "~/AppData/Local/Microsoft/Edge/User Data/**",
    "~/AppData/Roaming/Mozilla/Firefox/**", "~/AppData/Roaming/Microsoft/Credentials/**",
    "~/AppData/Local/Microsoft/Credentials/**", "~/.local/share/keyrings/**",
    "/etc/shadow", "/etc/sudoers", "/etc/ssl/private/**", "/proc/*/environ",
]

READ_TOOLS = ("Read", "Grep", "NotebookRead")
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")

ENV_DUMP = re.compile(
    r"(?:^|[;&|(]\s*)(?:env|printenv|export\s+-p|set)\s*(?:$|[;&|)>])|"
    r"\b(?:Get-ChildItem|gci|dir|ls)\s+env:|\[Environment\]::GetEnvironmentVariables|"
    r"/proc/(?:self|\d+|\*)/environ|\bcompgen\s+-v\b|^\s*(?:export|declare\s+-[xp]+|typeset\s+-x)\s*$|"
    r"\bprintenv\s+\w*(?:KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH)\w*|"
    r"\b(?:echo|printf|Write-(?:Host|Output))\b[^|;&\n]*\$(?:\{|env:)?\w*(?:KEY|TOKEN|SECRET|PASSW|CREDENTIAL)\w*",
    re.IGNORECASE | re.MULTILINE,
)


def classify(path: str, ctx: Context) -> Optional[str]:
    cfg = ctx.ccfg
    if not path:
        return None
    if util.path_matches(path, cfg.get("allow_patterns", [])):
        return None
    pats = PATTERNS + list(cfg.get("extra_patterns", []))
    # a directory like ~/.ssh should match the ~/.ssh/** pattern too
    return util.path_matches(path, pats) or util.path_matches(path.rstrip("/") + "/", pats)


def _candidate_tokens(cmd: str) -> List[str]:
    toks: List[str] = []
    # quoted strings inside scripts: python -c "open('.env').read()"
    toks += [q for q in re.findall(r"(?<=['\"])([^'\"\s]{1,200})(?=['\"])", cmd) if re.search(r"[/\\~.]", q)]
    for seg in util.split_commands(cmd):
        for t in util.tokenize(seg):
            t = t.strip("'\"()")
            t = re.sub(r"^\d?>{1,2}|^<", "", t)                   # redirections: >file, 2>file, <file
            t = re.sub(r"^--?[A-Za-z-]+=", "", t)                 # --file=path
            t = re.sub(r"^(?:-Path|-LiteralPath|-FilePath)[:=]?", "", t, flags=re.IGNORECASE)
            if t and not t.startswith("-") and (re.search(r"[/\\~.]|^id_|^env:", t) or "$" in t or "%" in t):
                toks.append(t)
    return toks


def shell_hits(cmd: str, ctx: Context) -> List[Tuple[str, str]]:
    hits = []
    for tok in _candidate_tokens(cmd):
        path = util.norm_path(tok, ctx.cwd)
        pat = classify(path, ctx)
        if pat:
            hits.append((tok, pat))
    return hits


def pre_tool(ctx: Context):
    cfg = ctx.ccfg
    tool, ti = ctx.tool, ctx.tool_input

    if tool in READ_TOOLS or tool in WRITE_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path") or ti.get("path") or ""
        if tool == "Grep" and not raw:
            raw = ctx.cwd  # Grep with no path searches the working directory
        if not isinstance(raw, str) or not raw:
            return None
        path = util.norm_path(raw, ctx.cwd)
        pat = classify(path, ctx)
        glob = ti.get("glob") if tool == "Grep" else None
        if not pat and isinstance(glob, str) and glob:
            glob = glob.replace("\\", "/").rsplit("/", 1)[-1]
            # Grep(path=".", glob=".env*") reads every .env under the tree
            probe = glob.replace("*", "").replace("{", "").replace("}", "").split(",")[0]
            pat = classify(path.rstrip("/") + "/" + probe, ctx)
        if not pat:
            return None
        action = cfg.get("read_action", "deny") if tool in READ_TOOLS else cfg.get("write_action", "ask")
        verb = "read" if tool in READ_TOOLS else "modify"
        reason = ("%s would %s %s, which matches the sensitive pattern '%s'. Its contents would enter "
                  "the conversation and the transcript. Ask the user to provide only the specific non-secret "
                  "value you need, or reference the variable name instead of its value." % (tool, verb, raw, pat))
        if action == "ask":
            reason = "Claude wants to %s a sensitive file: %s (matches '%s')." % (verb, raw, pat)
        return ctx.finding(action, reason=reason, audit_detail="%s %s (%s)" % (tool, path, pat))

    if ctx.is_shell and ctx.command:
        found = []
        cmd = util.neutralize(ctx.command)
        hits = shell_hits(cmd, ctx)
        if hits:
            found.append("references %s" % ", ".join("%s (%s)" % h for h in hits[:4]))
        if any(ENV_DUMP.search(s) for s in [cmd] + util.split_commands(cmd)):
            found.append("dumps environment variables (which usually hold tokens)")
        if found:
            action = cfg.get("shell_action", "ask")
            reason = "Shell command %s." % "; ".join(found)
            if action == "deny":
                reason += " Avoid printing secrets into the conversation; reference variable names instead."
            return ctx.finding(action, reason=reason, audit_detail=util.truncate(reason, 300))
    return None


# `@path` / `@"path with spaces"` file mentions. Claude Code attaches the file to the prompt itself,
# without a Read tool call, so PreToolUse never sees it: the prompt has to be stopped here.
AT_MENTION = re.compile(r"(?:^|(?<=[\s(\[{,;]))@(?:\"([^\"]+)\"|([^\s\"'`,;)\]}]+))")


def on_prompt(ctx: Context):
    prompt = ctx.event.get("prompt")
    if not isinstance(prompt, str) or "@" not in prompt:
        return None
    marker = ctx.cfg["checks"].get("prompt_gate", {}).get("override_marker") or "[[allow-sensitive]]"
    hits = []
    for m in AT_MENTION.finditer(prompt):
        raw = (m.group(1) or m.group(2) or "").rstrip(".:!?")
        if not raw:
            continue
        pat = classify(util.norm_path(raw, ctx.cwd), ctx)
        if pat:
            hits.append((raw, pat))
    if not hits:
        return None
    listed = ", ".join("@%s (matches %s)" % h for h in hits[:4])
    if marker in prompt:
        return ctx.finding("warn", user_msg="Attached sensitive file(s) with the override marker: " + listed,
                           audit_detail="override used: " + listed)
    return ctx.finding(
        "block",
        reason="Your prompt was NOT sent: it attaches %s, which would put the file's contents (likely "
               "secrets) into the conversation. Ask about the file without attaching it (for example "
               "\"which variables does .env define?\" lets Claude check names without values), or resend with "
               "%s if you really want the contents sent." % (listed, marker),
        audit_detail="blocked @-mention: " + listed)


HANDLERS = {"PreToolUse": pre_tool, "UserPromptSubmit": on_prompt}
