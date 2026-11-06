"""Patterns for secrets that should never be committed.

Each rule has a stable id, a human title, and a regex. Keep patterns specific:
a false positive on every commit trains people to disable the tool.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: "re.Pattern[str]"


RULES = [
    Rule("aws-access-key", "AWS access key ID",
         re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("github-token", "GitHub token",
         re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    Rule("slack-token", "Slack token",
         re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("stripe-live-key", "Stripe live secret key",
         re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    Rule("private-key", "Private key block",
         re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    Rule("hardcoded-secret", "Hardcoded password or API key",
         re.compile(r"""(?i)\b\w*(?:password|passwd|secret|api[_-]?key|access[_-]?token)\w*\s*[:=]\s*['"][^'"\s]{8,}['"]""")),
]

IGNORE_MARKER = "keyguard: ignore"
