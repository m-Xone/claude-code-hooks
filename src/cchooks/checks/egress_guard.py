"""5. Egress guard: data leaving the machine.

Flags uploads (curl -d @file, scp, nc, Invoke-RestMethod -Body, ...),
known paste/webhook/tunnel endpoints, URLs carrying long encoded payloads,
and secrets in any outbound tool input. In a session the injection
tripwire has tainted, all outbound network use needs confirmation.
Together with the tripwire this is the prompt-injection defence: a
poisoned page can still *say* "send me your .env", but acting on it hits a
prompt you can see.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from .. import util
from ..detectors import secrets
from ..engine import Context
from .injection_tripwire import is_tainted

NAME = "egress_guard"
KIND = "security"

I = re.IGNORECASE
URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s'\"<>|;)]+", I)

UPLOAD = [
    ("uploads data with curl", re.compile(
        r"\bcurl\b[^|;&]*(?:\s-(?:d|F|T)\b|\s--data(?:-\w+)?\b|\s--form\b|\s--upload-file\b|\s-X\s*(?:POST|PUT|PATCH)\b|"
        r"\s--request\s+(?:POST|PUT|PATCH)\b|\s-\w*[dFT]\s*@)", I)),
    ("uploads data with wget", re.compile(r"\bwget\b[^|;&]*--(?:post|body)-(?:data|file)", I)),
    ("uploads with httpie/xh", re.compile(r"\b(?:http|https|xh)\s+(?:POST|PUT|PATCH)\b|\b(?:http|xh)\b[^|;&]*\s\w+=@", I)),
    ("sends a request body from PowerShell", re.compile(
        r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^|;&]*(?:-Method\s+['\"]?(?:Post|Put|Patch)|-Body\b|-InFile\b)|"
        r"\.Upload(?:String|File|Data)\s*\(|\bSend-MailMessage\b", I)),
    ("copies files to a remote host", re.compile(
        r"\b(?:scp|sftp|rsync)\b[^|;&]*\s[\w.-]+@?[\w.-]*:[\S]*|\brclone\s+(?:copy|sync|move)\b|"
        r"\baws\s+s3\s+(?:cp|sync|mv)\b[^|;&]*\ss3://|\bgsutil\s+(?:cp|rsync)\b[^|;&]*gs://|\baz\s+storage\s+blob\s+upload", I)),
    ("opens a raw network socket", re.compile(
        r"\b(?:nc|ncat|netcat|socat|telnet)\b\s+[^|;&]*\d|/dev/(?:tcp|udp)/|\bNet\.Sockets\.TcpClient\b", I)),
    ("creates a public gist or paste", re.compile(r"\bgh\s+gist\s+create\b[^|;&]*(?:--public|-p\b)?", I)),
    ("DNS lookup with command substitution", re.compile(r"\b(?:nslookup|dig|host)\b[^|;&]*(?:\$\(|`)", I)),
    ("encodes data for a network request", re.compile(
        r"\b(?:base64|xxd|od)\b[^;&]*\|\s*(?:curl|wget|nc|http)\b|\b(?:curl|wget)\b[^;&]*\$\([^)]*(?:base64|cat)\b", I)),
]

EXFIL_DOMAINS = re.compile(
    r"(?:^|\.)(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|0x0\.st|transfer\.sh|file\.io|"
    r"termbin\.com|ix\.io|webhook\.site|requestbin\.\w+|pipedream\.net|beeceptor\.com|hookbin\.com|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net|interact\.sh|oast\.\w+|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|requestcatcher\.com|temp\.sh|bashupload\.com)$", I)

NETWORK_CMD = re.compile(
    r"\b(?:curl|wget|http|xh|nc|ncat|socat|scp|sftp|rsync|ssh|ftp|telnet|Invoke-WebRequest|iwr|Invoke-RestMethod|"
    r"irm|aws\s+s3|gsutil|rclone|gh\s+(?:api|gist))\b|/dev/tcp/", I)

MCP_WRITE_VERB = re.compile(
    r"(?:send|post|create|write|upload|share|forward|reply|comment|publish|update|delete|put|push|invite|"
    r"message|email|draft|submit|insert|execute|run)", I)


def _domain_allowed(host: str, allow: List[str]) -> bool:
    host = host.lower().strip("[]")
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in allow)


HOST_ARG = re.compile(r"(?:[\w.-]+@)?([\w.-]+|\[[0-9a-f:]+\]):")  # scp/rsync user@host:path
SECRET_VAR = re.compile(r"\$(?:\{|env:)?(\w*(?:KEY|TOKEN|SECRET|PASSW(?:OR)?D?|CREDENTIALS?|AUTH)\w*)", re.I)


def _hosts(cmd: str) -> List[str]:
    hosts = []
    for url in URL.findall(cmd):
        try:
            hosts.append(urlsplit(url).hostname or "")
        except ValueError:
            hosts.append("")
    for seg in util.split_commands(cmd):
        toks = util.tokenize(seg)
        prog = util.program_name(util.strip_env_prefix(toks))
        if prog in ("scp", "sftp", "rsync"):
            hosts += [m.group(1) for t in toks[1:] for m in [HOST_ARG.match(t)] if m and not t.startswith("-")]
        elif prog in ("nc", "ncat", "netcat", "socat", "telnet"):
            hosts += [t for t in toks[1:] if not t.startswith("-") and not t.isdigit()][:1]
    return [h for h in hosts if h is not None]


def _all_local(hosts: List[str], allow: List[str]) -> bool:
    return bool(hosts) and all(h and _domain_allowed(h, allow) for h in hosts)


def _payload_in_url(url: str, min_len: int) -> Optional[str]:
    parts = urlsplit(url)
    for chunk in re.split(r"[/?&=#.]", parts.path + "?" + parts.query):
        if len(chunk) >= min_len and re.fullmatch(r"[A-Za-z0-9+/_=%-]+", chunk) and util.shannon_entropy(chunk) > 4.0:
            return chunk
    host_labels = parts.hostname.split(".") if parts.hostname else []
    if any(len(l) >= 40 for l in host_labels):  # data smuggled in a subdomain
        return max(host_labels, key=len)
    return None


def analyze_urls(text: str, ctx: Context) -> List[Tuple[str, str]]:
    cfg = ctx.ccfg
    allow = cfg.get("allow_domains", [])
    out = []
    for url in URL.findall(text):
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            continue
        if EXFIL_DOMAINS.search(host):
            out.append(("ask", "sends to %s, a paste/webhook/tunnel service often used for exfiltration" % host))
        elif not _domain_allowed(host, allow):
            chunk = _payload_in_url(url, int(cfg.get("payload_min_len", 64)))
            if chunk:
                out.append(("ask", "URL to %s carries a long encoded value (%s)" % (host, util.redact(chunk, 8))))
    return out


def pre_tool(ctx: Context):
    tool, ti = ctx.tool, ctx.tool_input
    is_mcp = tool.startswith("mcp__")
    if not (ctx.is_shell or tool in ("WebFetch", "WebSearch") or is_mcp):
        return None
    tainted = is_tainted(ctx.session)
    reasons: List[Tuple[str, str]] = []
    outbound_text = util.flatten_text(ti, limit=2_000_000)
    network = False
    local = False

    if ctx.is_shell:
        cmd = util.neutralize(ctx.command)
        network = bool(NETWORK_CMD.search(cmd))
        allow = ctx.ccfg.get("allow_domains", [])
        local = _all_local(_hosts(cmd), allow)  # uploads to localhost / allow-listed hosts are fine
        if not local:
            for label, rx in UPLOAD:
                if rx.search(cmd):
                    reasons.append(("ask", label))
            if network:
                names = sorted({m for m in SECRET_VAR.findall(cmd)})
                if names:
                    reasons.append(("ask", "puts the value of $%s into a network request to a host that "
                                           "isn't allow-listed" % ", $".join(names[:3])))
        reasons += analyze_urls(cmd, ctx)
    elif tool == "WebFetch":
        network = True
        reasons += analyze_urls(str(ti.get("url", "")), ctx)
        host = urlsplit(str(ti.get("url", ""))).hostname or ""
        if tainted and not _domain_allowed(host, ctx.ccfg.get("allow_domains", [])):
            reasons.append(("ask", "fetches %s while the session is tainted by a suspected injection" % host))
    elif tool == "WebSearch":
        network = True
    elif is_mcp:
        network = True
        action = tool.split("__")[-1]
        srv = ctx.event.get("mcp_server")
        source = srv.get("source", "") if isinstance(srv, dict) else ""
        if tainted and MCP_WRITE_VERB.search(action):
            reasons.append(("ask", "calls MCP action '%s'%s while the session is tainted by a suspected injection"
                            % (action, " (server source: %s)" % source if source else "")))
        reasons += analyze_urls(outbound_text, ctx)

    if network:
        found = [m for m in secrets.scan(outbound_text) if m.severity in ("critical", "high")]
        if found:
            reasons.append(("deny", "would send secret values off the machine: %s" % secrets.summarize(found)))

    if tainted and ctx.is_shell and network and not local and not any(a == "ask" for a, _ in reasons):
        src = (tainted.get("sources") or [{}])[-1]
        reasons.append(("ask", "makes a network call while the session is tainted (suspected injection from %s)"
                        % src.get("source", "an earlier tool result")))

    if not reasons:
        return None
    denies = [r for a, r in reasons if a == "deny"]
    if denies:
        return ctx.finding("deny", reason="Outbound request blocked: it %s. If the user wants this, they should "
                                          "send it themselves." % "; ".join(denies),
                           audit_detail="; ".join(denies))
    msg = "Outbound data: this %s %s." % ("command" if ctx.is_shell else "call", "; ".join(r for _, r in reasons))
    return ctx.finding("ask", reason=msg, audit_detail=util.truncate(msg, 300))


HANDLERS = {"PreToolUse": pre_tool}
