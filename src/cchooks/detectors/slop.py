"""Scores prose for common LLM writing tells.

A single tell is not slop; density is. The score is roughly "tells per 150
words" plus fixed penalties for openers and closers, so short replies with
one "Certainly!" still register and long documents aren't punished for
length. Code blocks, inline code and quoted lines are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

I = re.IGNORECASE | re.MULTILINE

# (label, weight, pattern)
PATTERNS: List[Tuple[str, float, "re.Pattern[str]"]] = [
    # sycophancy / servile framing
    ("sycophantic opener", 3, re.compile(r"\A\W*(?:great|excellent|fantastic|wonderful|good|awesome|brilliant)\s+"
                                         r"(?:question|idea|point|catch|observation|thinking)\b", I)),
    ("sycophantic opener", 3, re.compile(r"\A\W*(?:absolutely|certainly|of course|sure thing|definitely)[!,.]", I)),
    ("sycophancy", 2, re.compile(r"\byou(?:'re| are) (?:absolutely|completely|totally|so) right\b", I)),
    ("eager helper", 1.5, re.compile(r"\bI(?:'d| would) be (?:happy|glad|delighted) to\b", I)),
    ("stock closer", 2, re.compile(r"\b(?:I hope (?:this|that) helps|hope this helps|happy coding|let me know if you "
                                   r"(?:have any|need any|want me|would like)|feel free to (?:reach out|ask|let me know))\b", I)),
    # structural tells
    ("not-X-but-Y", 2, re.compile(r"\b(?:it'?s|this is|that'?s|isn'?t|is not|was not|wasn'?t)\s+not\s+(?:just|only|merely|simply|about)?\s*"
                                  r"[^.;:!?\n]{1,50}[,;—–-]+\s*(?:it'?s|but|rather)\b", I)),
    ("not-X-but-Y", 2, re.compile(r"\bnot (?:just|only|merely|simply) (?:a |an |the )?[^.;:!?\n]{1,40}?,? but (?:also |rather )?", I)),
    ("not-X. It's-Y", 2, re.compile(r"\b(?:isn'?t|is not|wasn'?t|it'?s not)\s+(?:just\s+|merely\s+|simply\s+)?(?:about\s+)?"
                                    r"[^.!?\n]{1,40}\.\s+(?:it'?s|it is|this is)\b", I)),
    ("dramatic reveal", 2, re.compile(r"(?:^|\. )(?:here'?s the (?:kicker|thing|catch|twist)|the best part\?|spoiler:|"
                                      r"the result\?|the answer\?|the truth\?|plot twist)", I)),
    ("hype signpost", 1.5, re.compile(r"\b(?:let'?s (?:dive|delve|jump) (?:in|into|right in)|buckle up|without further ado|"
                                      r"in today'?s (?:fast-paced|digital|ever-changing|modern) (?:world|landscape|age))\b", I)),
    ("hedge filler", 1, re.compile(r"\b(?:it'?s (?:worth|important to) (?:noting|note|mention|remember)|it is (?:worth|important) to "
                                   r"(?:note|mention|remember)|keep in mind that|needless to say)\b", I)),
    ("summary boilerplate", 1, re.compile(r"(?:^|\n)\s*(?:in (?:conclusion|summary)|to summarize|overall|ultimately)[,:]", I)),
    # vocabulary
    ("AI vocabulary", 1, re.compile(r"\b(?:delv(?:e|es|ing)|tapestry|testament to|seamless(?:ly)?|leverag(?:e|es|ing)(?= (?:the|our|your|this|a|an)\b)|"
                                    r"utiliz(?:e|es|ing)|harness(?:es|ing)? the power|unlock(?:s|ing)? the (?:power|potential|full)|"
                                    r"elevat(?:e|es|ing) (?:your|the|our)|embark(?:s|ing)? on|navigat(?:e|es|ing) the (?:complexities|intricacies|landscape)|"
                                    r"ever-(?:evolving|changing)|realm of|paramount|pivotal|meticulous(?:ly)?|intricacies|bustling|vibrant|"
                                    r"game[- ]changer|cutting[- ]edge|myriad|plethora|underscor(?:e|es|ing)|showcas(?:e|es|ing)|"
                                    r"foster(?:s|ing)?|bolster(?:s|ing)?|empower(?:s|ing)?|holistic|synerg(?:y|ies)|deep dive|"
                                    r"rich tapestry|in the realm|a testament|nuanced|robust and scalable|streamlin(?:e|es|ing))\b", I)),
    ("transition stacking", 0.75, re.compile(r"(?:^|[.!?]\s+)(?:moreover|furthermore|additionally|notably|consequently|importantly),", I)),
    ("emoji bullets", 1, re.compile(r"(?m)^\s*(?:[-*]\s*)?[✅✨\U0001F680\U0001F4A1\U0001F3AF\U0001F525\U0001F4CC\U0001F31F⚡]\s")),
]


@dataclass
class SlopReport:
    score: float
    words: int
    hits: Dict[str, int] = field(default_factory=dict)
    em_dash_per_100: float = 0.0

    def summary(self, limit: int = 6) -> str:
        items = sorted(self.hits.items(), key=lambda kv: -kv[1])[:limit]
        parts = ["%s ×%d" % (k, v) if v > 1 else k for k, v in items]
        if self.em_dash_per_100 >= 1.5:
            parts.append("em-dash density %.1f/100 words" % self.em_dash_per_100)
        return ", ".join(parts)


def _clean(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"~~~.*?~~~", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`\n]*`", " ", text)
    text = re.sub(r"(?m)^\s*>.*$", " ", text)       # quotations
    text = re.sub(r"https?://\S+", " ", text)
    return text


def score(text: str, extra_phrases: List[str] = ()) -> SlopReport:
    body = _clean(text or "")
    words = len(re.findall(r"[A-Za-z']+", body))
    if words < 12:
        return SlopReport(0.0, words)
    hits: Dict[str, int] = {}
    fixed = 0.0    # openers/closers: counted once, never diluted by length
    density = 0.0  # everything else: dampened by sqrt(length) so long docs aren't punished
    for label, weight, rx in PATTERNS:
        n = len(rx.findall(body))
        if not n:
            continue
        hits[label] = hits.get(label, 0) + n
        if "opener" in label or "closer" in label:
            fixed += weight
        else:
            density += weight * n
    for phrase in extra_phrases:
        n = len(re.findall(r"\b%s\b" % re.escape(phrase), body, re.IGNORECASE))
        if n:
            hits[phrase] = n
            density += n
    # one "fast, reliable, and secure" is English; a habit of them is a tell
    triads = len(re.findall(r"\b\w+, \w+, and \w+\b", body))
    if triads >= 3:
        hits["rule-of-three lists"] = triads
        density += triads - 2
    dashes = body.count("—") + len(re.findall(r"\s--\s", body))
    dash_density = dashes * 100.0 / words
    if dash_density >= 1.5:
        density += min(4.0, (dash_density - 1.0) * 1.5)
    total = fixed + density * (150.0 / max(words, 150)) ** 0.5
    return SlopReport(round(total, 1), words, hits, round(dash_density, 2))
