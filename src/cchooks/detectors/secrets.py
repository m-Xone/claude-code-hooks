"""Secret and PII detection shared by the prompt gate, the secret-leak
check, and the egress guard, so all three agree on what a secret is.

Each match carries a severity:
  critical  private keys, cloud root credentials
  high      provider API tokens, card numbers, SSNs, IBANs, passwords in URLs
  medium    JWTs, generic `secret = "..."` assignments with high entropy
  low       email addresses, phone numbers
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern

from ..util import redact, shannon_entropy


@dataclass
class Match:
    kind: str
    severity: str
    start: int
    end: int
    value: str

    @property
    def preview(self) -> str:
        if self.kind in ("credit_card",):
            digits = re.sub(r"\D", "", self.value)
            return "card ending %s" % digits[-4:]
        if self.kind in ("us_ssn", "iban", "phone"):
            return "%s…%s" % (self.value[:2], self.value[-2:])
        if self.kind == "email":
            user, _, dom = self.value.partition("@")
            return "%s…@%s" % (user[:1], dom)
        if self.kind == "private_key":
            return self.value[:40]
        return redact(self.value)


@dataclass
class Rule:
    kind: str
    severity: str
    rx: Pattern[str]
    group: int = 0
    validate: Optional[Callable[[str], bool]] = None


# Values that are obviously documentation or templates, never real.
_PLACEHOLDER = re.compile(
    r"(?i)example|x{5,}|\*{3,}|\.{3,}|<[^>]*>|\$\{|\{\{|%\(|your[_-]|changeme|placeholder|"
    r"redacted|dummy|fake|sample|replace[_-]?me|insert[_-]|todo|^(?:test|secret|password|token)$"
)


def _not_placeholder(v: str) -> bool:
    return not _PLACEHOLDER.search(v)


def _generic_ok(v: str) -> bool:
    v = v.strip("'\"")
    if not _not_placeholder(v) or len(v) < 12:
        return False
    if re.fullmatch(r"[a-z_.]+\(?.*", v) and "(" in v:  # function call: os.getenv(...)
        return False
    if re.fullmatch(r"[A-Z_][A-Z0-9_]*", v):  # env var name
        return False
    if re.fullmatch(r"[\w./-]+\.(?:py|js|ts|json|yaml|yml|txt|md)", v):  # a file name
        return False
    return shannon_entropy(v) >= 3.5 and bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v))


def _luhn(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    if total % 10:
        return False
    num = "".join(map(str, digits))
    return bool(re.match(r"4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35|3[068]", num))


def _iban(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in moved)
    return int(num) % 97 == 1


def _url_password(v: str) -> bool:
    return _not_placeholder(v) and v.lower() not in ("password", "pass", "pwd", "secret", "x", "user")


R = re.compile
RULES: List[Rule] = [
    Rule("private_key", "critical", R(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    Rule("aws_access_key", "critical", R(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), validate=_not_placeholder),
    Rule("aws_secret_key", "critical",
         R(r"(?i)aws.{0,24}(?:secret|private).{0,16}[=:>\"'\s]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
         group=1, validate=_not_placeholder),
    Rule("gcp_service_account", "critical", R(r"\"private_key_id\"\s*:\s*\"[0-9a-f]{40}\"")),
    Rule("azure_storage_key", "critical", R(r"AccountKey=([A-Za-z0-9+/=]{80,90})"), group=1),
    Rule("github_token", "high", R(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b")),
    Rule("gitlab_token", "high", R(r"(?<![A-Za-z0-9_\-])glpat-[A-Za-z0-9_\-]{20,256}")),
    Rule("anthropic_key", "high", R(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,256}")),
    Rule("openai_key", "high", R(r"(?<![A-Za-z0-9_\-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,256}|(?<![A-Za-z0-9_\-])sk-[A-Za-z0-9]{48}\b")),
    Rule("stripe_key", "high", R(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,256}\b")),
    Rule("stripe_test_key", "medium", R(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,256}\b")),
    Rule("slack_token", "high", R(r"(?<![A-Za-z0-9_\-])xox[abposr]-[A-Za-z0-9-]{10,256}")),
    Rule("slack_webhook", "high", R(r"https://hooks\.slack\.com/services/T[A-Z0-9]{1,32}/B[A-Z0-9]{1,32}/[A-Za-z0-9]{1,64}")),
    Rule("discord_webhook", "high", R(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{1,32}/[\w-]{30,128}")),
    Rule("google_api_key", "high", R(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("google_oauth_secret", "high", R(r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b")),
    Rule("sendgrid_key", "high", R(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    Rule("npm_token", "high", R(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Rule("pypi_token", "high", R(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,512}")),
    Rule("huggingface_token", "high", R(r"\bhf_[A-Za-z0-9]{34,128}\b")),
    Rule("twilio_key", "high", R(r"\bSK[0-9a-f]{32}\b")),
    Rule("digitalocean_token", "high", R(r"\bdo[pro]_v1_[a-f0-9]{64}\b")),
    Rule("shopify_token", "high", R(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b")),
    Rule("databricks_token", "high", R(r"\bdapi[a-f0-9]{32}\b")),
    Rule("url_password", "high",
         R(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\"']{1,64}:([^\s:@/\"']{3,128})@[^\s/\"']{1,253}"),
         group=1, validate=_url_password),
    Rule("jwt", "medium", R(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{10,4096}\.eyJ[A-Za-z0-9_\-]{10,4096}\.[A-Za-z0-9_\-]{10,4096}")),
    Rule("generic_secret", "medium",
         R(r"(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"
           r"client[_-]?secret|passw(?:or)?d|pwd|private[_-]?key)\b[\"']?\s*(?:=|:|=>|:=)\s*"
           r"[\"']?([^\s\"',;]{12,512})"),
         group=1, validate=_generic_ok),
]

PII_RULES: List[Rule] = [
    Rule("credit_card", "high", R(r"(?<![\d.-])(?:\d[ -]?){12,18}\d(?![\d-])"), validate=_luhn),
    Rule("us_ssn", "high", R(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    Rule("iban", "high", R(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"), validate=_iban),
    Rule("email", "low", R(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"),
         validate=lambda v: not re.search(r"(?i)@(?:example\.(?:com|org|net)|test\.com|localhost|users\.noreply\.github\.com)$|^(?:noreply|no-reply|git)@", v)),
    Rule("phone", "low", R(r"(?<![\w+])(?:\+?1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}\b|\+(?:[2-9]\d{0,2})[ .-]?\d{2,4}[ .-]\d{3,4}[ .-]\d{3,4}\b")),
]


def scan(text: str, secrets: bool = True, pii: bool = False, max_len: int = 4_000_000) -> List[Match]:
    """All non-overlapping matches, most severe first when two overlap."""
    if not text:
        return []
    text = text[:max_len]
    rules = (RULES if secrets else []) + (PII_RULES if pii else [])
    found: List[Match] = []
    for rule in rules:
        for m in rule.rx.finditer(text):
            val = m.group(rule.group) if rule.group else m.group(0)
            if not val:
                continue
            if not (rule.validate or _not_placeholder)(val):
                continue
            found.append(Match(rule.kind, rule.severity, m.start(rule.group), m.end(rule.group), val))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found.sort(key=lambda x: (order[x.severity], x.start))
    kept: List[Match] = []
    for f in found:
        if not any(f.start < k.end and k.start < f.end for k in kept):
            kept.append(f)
    return kept


def redact_text(text: str, matches: List[Match]) -> str:
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        text = text[: m.start] + "[REDACTED:%s]" % m.kind + text[m.end:]
    return text


def summarize(matches: List[Match], limit: int = 6) -> str:
    parts = ["%s (%s)" % (m.kind, m.preview) for m in matches[:limit]]
    if len(matches) > limit:
        parts.append("+%d more" % (len(matches) - limit))
    return ", ".join(parts)
