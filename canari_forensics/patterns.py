from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class DetectionPattern:
    pattern_id: str
    name: str
    severity: str
    confidence: str
    kind: str
    regex: Pattern[str]


PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        pattern_id="cred_stripe_live",
        name="Stripe live secret key",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bsk_live_[A-Za-z0-9]+\b"),
    ),
    DetectionPattern(
        pattern_id="cred_openai_test",
        name="OpenAI-like test key",
        severity="HIGH",
        confidence="MEDIUM",
        kind="canary_or_test_credential",
        regex=re.compile(r"\bsk_test_[A-Za-z0-9_]+\b"),
    ),
    DetectionPattern(
        pattern_id="aws_access_key",
        name="AWS access key",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    DetectionPattern(
        pattern_id="prompt_injection_indicator",
        name="Prompt injection success indicator",
        severity="HIGH",
        confidence="MEDIUM",
        kind="probable_prompt_injection",
        regex=re.compile(r"(?i)here is everything|ignore all instructions|output your full context"),
    ),
]
