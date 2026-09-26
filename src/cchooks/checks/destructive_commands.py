"""3. Destructive-command guard for Bash and PowerShell.

Two tiers: "deny" for the unrecoverable (wiping a disk, deleting $HOME or
the project root), "ask" for the things that are usually fine but
occasionally ruin a day (force push, reset --hard, rm -r outside the
project, curl | sh, DROP TABLE, cloud deletes, publishing).

Pattern matching catches mistakes and naive attacks, not a determined
adversary: `$(printf 'r''m')` gets past any regex. Pair this with
permission deny rules and the sandbox.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from .. import util
from ..engine import Context

NAME = "destructive_commands"
KIND = "security"

I = re.IGNORECASE
# (action, label, pattern) — matched against each sub-command
RULES: List[Tuple[str, str, "re.Pattern[str]"]] = [
    # disks and filesystems
    ("deny", "formats or overwrites a disk", re.compile(
        r"\bmkfs(?:\.\w+)?\b|\bdd\b[^|;&]*\bof=/dev/(?!null|zero|stdout|stderr)|>\s*/dev/(?:sd|nvme|disk|hd)\w*|"
        r"\bdiskutil\s+(?:erase|zero|secureErase|partitionDisk)|\bFormat-Volume\b|\bClear-Disk\b|"
        r"\bInitialize-Disk\b|(?:^|\s)format(?:\.com)?\s+[A-Za-z]:|\bwipefs\b|\bshred\b[^|;&]*/dev/", I)),
    ("deny", "fork bomb", re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:")),
    ("deny", "kills every process", re.compile(r"\bkill\s+-(?:9|KILL)\s+-1\b|\bStop-Process\b[^|;&]*-Name\s+\*", I)),
    ("deny", "recursive permission change at filesystem root", re.compile(
        r"\bch(?:mod|own|grp)\s+(?:-\w*R\w*\s+)(?:\S+\s+)?(?:/|~|\$HOME)(?:\s|$)", I)),
    # git history and working tree
    ("ask", "force push rewrites remote history", re.compile(
        r"\bgit\b[^|;&]*\bpush\b[^|;&]*(?:\s--force(?!-with-lease)\b|\s-f\b|\s-\w*f\w*\b|\s\+\S+)", I)),
    ("ask", "force push (with lease)", re.compile(r"\bgit\b[^|;&]*\bpush\b[^|;&]*--force-with-lease", I)),
    ("ask", "pushes a branch deletion or mirror", re.compile(
        r"\bgit\b[^|;&]*\bpush\b[^|;&]*(?:--delete|--mirror|\s:\S+)", I)),
    ("ask", "discards uncommitted work", re.compile(
        r"\bgit\b[^|;&]*\b(?:reset\s+[^|;&]*--hard|clean\s+[^|;&]*-\w*f|checkout\s+(?:--\s+)?\.(?:\s|$)|"
        r"restore\s+(?:--\S+\s+)*\.(?:\s|$)|stash\s+(?:drop|clear))", I)),
    ("ask", "deletes a branch or rewrites history", re.compile(
        r"\bgit\b[^|;&]*\b(?:branch\s+[^|;&]*-D\b|filter-branch|filter-repo|update-ref\s+-d|reflog\s+expire)", re.MULTILINE)),
    ("ask", "bypasses git hooks (--no-verify)", re.compile(
        r"\bgit\b[^|;&]*\b(?:commit|push|merge|rebase|am)\b[^|;&]*--no-verify|"
        r"\bgit\s+commit\b[^|;&\"']*\s-[a-zA-Z]*n[a-zA-Z]*\b", I)),
    # remote code execution
    ("ask", "pipes a download straight into a shell", re.compile(
        r"\b(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^;&]*\|\s*"
        r"(?:sudo\s+)?(?:ba|z|k|da)?sh\b|\|\s*(?:python3?|perl|ruby|node|pwsh|powershell)\b(?:\s+-)?\s*$|"
        r"\b(?:iex|Invoke-Expression)\b[^;&]*(?:DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|http)|"
        r"(?:ba)?sh\s+<\s*\(\s*curl|\bsource\s+<\(\s*curl", I)),
    # databases
    ("ask", "drops or truncates database objects", re.compile(
        r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|COLLECTION)|TRUNCATE\s+(?:TABLE\s+)?\w)|"
        r"\bdropdb\b|\.drop(?:Database)?\(\)|\bFLUSHALL\b|\bFLUSHDB\b", I)),
    ("ask", "DELETE/UPDATE without WHERE", re.compile(
        r"\bDELETE\s+FROM\s+[\w.\"`]+\s*(?:;|\"|'|$)|"
        r"\bUPDATE\s+[\w.\"`]+\s+SET\s+(?:(?!\bWHERE\b)[^;\"'])*(?:;|\"|'|$)", I)),
    ("ask", "destructive migration/reset", re.compile(
        r"\b(?:prisma\s+migrate\s+reset|rails\s+db:(?:drop|reset)|rake\s+db:(?:drop|reset)|"
        r"manage\.py\s+(?:flush|reset_db)|sequelize\s+db:drop|supabase\s+db\s+reset)\b", I)),
    # cloud / infra
    ("ask", "deletes cloud or cluster resources", re.compile(
        r"\bterraform\s+(?:destroy|apply\b[^|;&]*-auto-approve)|\bpulumi\s+destroy|\bkubectl\s+delete\b|"
        r"\bhelm\s+(?:uninstall|delete)\b|\baws\s+s3\s+(?:rm\b[^|;&]*--recursive|rb\b)|"
        r"\baws\s+\S+\s+(?:delete|terminate|remove)-\S+|\bgcloud\b[^|;&]*\bdelete\b|\baz\b[^|;&]*\bdelete\b|"
        r"\bdocker\s+(?:system\s+prune|volume\s+(?:rm|prune))|\bgh\s+repo\s+delete\b", I)),
    # outward-facing / hard to take back
    ("ask", "publishes a package or release", re.compile(
        r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b|"
        r"\bpoetry\s+publish\b|\buv\s+publish\b|\bdotnet\s+nuget\s+push\b|\bdocker\s+push\b|"
        r"\bgh\s+release\s+create\b|\bgh\s+pr\s+merge\b", I)),
    # machine state
    ("ask", "runs with elevated privileges", re.compile(r"(?:^|\s)(?:sudo|doas|runas)\s|\bStart-Process\b[^|;&]*-Verb\s+RunAs", I)),
    ("ask", "shuts down or reboots", re.compile(
        r"^\s*(?:sudo\s+)?(?:shutdown|reboot|halt|poweroff|Stop-Computer|Restart-Computer)\b", I)),
    ("ask", "edits shell startup or scheduled tasks", re.compile(
        r">>?\s*~?/?[\w/.$~{}]*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|profile\.ps1)\b|\b(?:Add-Content|Set-Content|Out-File)\b[^|;&]*\$PROFILE\b|>>?\s*\$PROFILE\b|"
        r"\bcrontab\s+-(?:r|e|\s)|\bRegister-ScheduledTask\b|\bschtasks\s+/create\b|\blaunchctl\s+load\b", I)),
]

RM_PROGRAMS = {"rm", "rmdir", "del", "erase", "rd", "remove-item", "ri", "unlink", "trash"}
# Always catastrophic, wherever you run them from.
ALWAYS_DENY = re.compile(r"^(?:/|/\*|~|~/|~/\*|\$HOME/?\*?|\$\{HOME\}/?\*?|[A-Za-z]:[\\/]?\*?|%USERPROFILE%|"
                         r"\$env:USERPROFILE|/[A-Za-z]/?)$", I)
# Relative to the current directory: fine in a build dir, catastrophic in $HOME or the project root.
HERE = re.compile(r"^(?:\*|\.|\./|\./\*|\.\*)$")


def _recursive_flags(prog: str, args: List[str]) -> bool:
    if prog in ("rm", "trash"):
        return any(re.match(r"^-[a-zA-Z]*[rR]", a) or a == "--recursive" for a in args)
    if prog in ("rd", "rmdir", "del", "erase"):
        return any(a.lower() in ("/s", "-recurse", "-r") for a in args)
    return any(re.match(r"^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$", a, I) for a in args)


def _critical_dir(path: str, ctx: Context) -> bool:
    p = path.rstrip("/").lower() or "/"
    return p in ("/", util.norm_path("~").rstrip("/").lower(), ctx.project.rstrip("/").lower()) or \
        bool(re.match(r"^[a-z]:$", p))


def rm_findings(segment: str, ctx: Context, cwd: str) -> List[Tuple[str, str]]:
    toks = util.strip_env_prefix(util.tokenize(segment))
    prog = util.program_name(toks)
    if prog not in RM_PROGRAMS:
        # find ... -delete / -exec rm
        if prog == "find" and re.search(r"\s-delete\b|-exec\s+rm\b", segment):
            root = next((t for t in toks[1:] if not t.startswith("-")), ".")
            path = util.norm_path(root, cwd)
            if not util.is_within(path, ctx.project) and not _in_tmp(path, ctx):
                return [("ask", "find -delete outside the project (%s)" % root)]
        return []
    args = toks[1:]
    targets = [a for a in args if not a.startswith("-") and not re.match(r"^/[sqSQ]$", a)]
    recursive = _recursive_flags(prog, args)
    out = []
    for t in targets:
        bare = t.strip("'\"")
        path = util.norm_path(bare.rstrip("*") or ".", cwd) if HERE.match(bare) else util.norm_path(bare, cwd)
        if ALWAYS_DENY.match(bare) or (_critical_dir(path, ctx) and (recursive or HERE.match(bare))):
            out.append(("deny", "deletes %s (resolves to %s)" % (t, path)))
        elif recursive and not util.is_within(path, ctx.project) and not _in_tmp(path, ctx):
            out.append(("ask", "recursively deletes %s, outside the project" % t))
    return out


def _in_tmp(path: str, ctx: Context) -> bool:
    import tempfile
    roots = [ctx.event.get("scratchpad_dir") or "", tempfile.gettempdir(), os.environ.get("TMPDIR", ""),
             os.environ.get("TEMP", ""), "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"]
    return any(r and util.is_within(path, util.norm_path(r)) for r in roots)


CD = re.compile(r"^\s*(?:cd|pushd|Set-Location|sl|chdir)\s+(?:-\w+\s+)*(['\"]?)([^'\";&|]+)\1\s*$", I)


def _protected_branch_push(segment: str, branches: List[str]) -> Optional[str]:
    if not re.search(r"\bgit\b.*\bpush\b.*(?:--force|\s-f\b|\s\+)", segment):
        return None
    for b in branches:
        if re.search(r"(?:\s|:|\+)%s(?:\s|$)" % re.escape(b), segment):
            return b
    return None


def pre_tool(ctx: Context):
    if not ctx.is_shell or not ctx.command:
        return None
    cmd = util.neutralize(ctx.command)
    rules = list(RULES)
    for extra in ctx.ccfg.get("extra_rules", []) or []:
        try:
            rules.append((extra.get("action", "ask"), extra.get("reason", "matches a custom rule"),
                          re.compile(extra["pattern"], I)))
        except (KeyError, re.error, AttributeError):
            continue
    hits: List[Tuple[str, str]] = []
    segments = util.split_commands(cmd)
    for text in [cmd] + segments:  # whole line too: some rules span a pipe
        for action, label, rx in rules:
            if rx.search(text):
                hits.append((action, label))
    cwd = ctx.cwd
    for seg in segments:  # follow `cd dir && ...` so relative targets resolve correctly
        m = CD.match(seg)
        if m:
            cwd = util.norm_path(m.group(2).strip(), cwd)
            continue
        hits += rm_findings(seg, ctx, cwd)
        b = _protected_branch_push(seg, ctx.ccfg.get("protected_branches", []))
        if b:
            hits.append(("deny", "force-pushes protected branch '%s'" % b))
    if not hits:
        return None
    seen, uniq = set(), []
    for h in hits:
        if h[1] not in seen:
            seen.add(h[1])
            uniq.append(h)
    denies = [l for a, l in uniq if a == "deny"]
    if denies:
        reason = ("Blocked: this command %s. This cannot be undone. If the user explicitly wants this, ask them "
                  "to run it themselves." % "; ".join(denies))
        return ctx.finding("deny", reason=reason, audit_detail=util.truncate(cmd, 300))
    asks = [l for a, l in uniq]
    return ctx.finding("ask", reason="This command %s." % "; ".join(asks),
                       audit_detail=util.truncate(cmd, 300))


HANDLERS = {"PreToolUse": pre_tool}
