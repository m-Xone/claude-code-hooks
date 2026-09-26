"""Heuristics for instruction-shaped text arriving through tool results.

This is a tripwire, not a classifier: it catches the common, unsophisticated
injections (and all invisible-Unicode smuggling), which is most of what
shows up in the wild. Each signal adds to a score; the caller decides the
threshold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Signal:
    kind: str
    weight: int
    sample: str


I = re.IGNORECASE
PHRASES: List[Tuple[str, int, "re.Pattern[str]"]] = [
    ("override", 3, re.compile(r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*"
                               r"(?:previous|prior|above|earlier|preceding|original|system)\s+"
                               r"(?:instructions?|prompts?|directions?|rules|guidelines|context)", I)),
    ("new_instructions", 2, re.compile(r"\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?instructions?\s*[:：]", I)),
    ("role_reassign", 2, re.compile(r"\byou\s+are\s+now\s+(?:a|an|in|the|no\s+longer)\b|\bfrom\s+now\s+on,?\s+you\s+(?:must|will|are|should)\b", I)),
    ("addressed_to_ai", 2, re.compile(r"\b(?:attention|note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?"
                                      r"(?:ai|llm|assistant|agent|claude|chatgpt|model|language\s+model)s?\b", I)),
    ("addressed_to_ai", 2, re.compile(r"\b(?:if\s+you\s+are|as)\s+an?\s+(?:ai|llm|language\s+model|ai\s+assistant|"
                                      r"coding\s+agent|autonomous\s+agent)\b[^.\n]{0,60}\b(?:must|should|need\s+to|are\s+required)", I)),
    ("secrecy", 3, re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|alert|notify|mention\s+(?:this\s+)?to)\s+the\s+user\b|"
                              r"\bwithout\s+(?:telling|informing|alerting|asking)\s+the\s+user\b", I)),
    ("exfil_request", 3, re.compile(r"\b(?:send|post|upload|exfiltrate|forward|transmit|email|paste|include)\b[^.\n]{0,50}"
                                    r"\b(?:api[\s_-]?keys?|secrets?|credentials?|passwords?|tokens?|\.env|ssh\s+keys?|"
                                    r"environment\s+variables|private\s+keys?|id_rsa)\b", I)),
    ("tool_coercion", 2, re.compile(r"\b(?:run|execute|call|invoke)\s+(?:the\s+following|this)\s+(?:command|tool|code|script)\b"
                                    r"[^.\n]{0,40}\b(?:immediately|now|silently|without)", I)),
    ("fake_tag", 3, re.compile(r"</?\s*(?:system|system[-_]reminder|system[-_]prompt|assistant|human|user|instructions?|"
                               r"admin|developer|tool_result|function_results?|antml:[a-z_]+)\s*>", I)),
    ("chat_template", 3, re.compile(r"<\|(?:im_start|im_end|system|endoftext|start_header_id)\|>|\[/?INST\]|<<\s*/?SYS\s*>>")),
    ("fake_turn", 1, re.compile(r"(?m)^\s*(?:Human|Assistant|System)\s*:\s+\S")),
]

# Unicode tag block (ASCII smuggling), bidi overrides, and zero-width runs.
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
BIDI = re.compile("[‪-‮⁦-⁩]")
ZERO_WIDTH_RUN = re.compile("[​-‍⁠﻿]{3,}")


def decode_tag_chars(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in TAG_CHARS.findall(text) if 0x20 <= ord(c) - 0xE0000 < 0x7F)


def scan(text: str, max_len: int = 400_000) -> List[Signal]:
    text = text[:max_len]
    out: List[Signal] = []
    if TAG_CHARS.search(text):
        out.append(Signal("unicode_tags", 5, "hidden text: " + decode_tag_chars(text)[:80]))
    if BIDI.search(text):
        out.append(Signal("bidi_override", 2, "bidirectional control characters"))
    if ZERO_WIDTH_RUN.search(text):
        out.append(Signal("zero_width", 2, "run of zero-width characters"))
    seen = set()
    for kind, weight, rx in PHRASES:
        m = rx.search(text)
        if m and kind not in seen:
            seen.add(kind)
            s = text[max(0, m.start() - 20): m.end() + 20]
            out.append(Signal(kind, weight, " ".join(s.split())[:120]))
    return out


def score(signals: List[Signal]) -> int:
    return sum(s.weight for s in signals)
