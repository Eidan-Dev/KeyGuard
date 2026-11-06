"""Find secrets in files, or in the changes about to be committed."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from .patterns import IGNORE_MARKER, RULES, Rule

IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 1_000_000
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")


@dataclass
class Finding:
    path: str
    line: int
    rule: Rule
    snippet: str


def redact(value: str) -> str:
    """Show just enough to recognize the key, never the whole secret."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * 8 + "…"


def scan_line(path: str, line_no: int, text: str) -> List[Finding]:
    if IGNORE_MARKER in text:
        return []
    findings = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            if rule.id == "hardcoded-secret":
                shown = _redact_quoted_value(match.group(0), text)
            else:
                shown = text.replace(match.group(0), redact(match.group(0)))
            findings.append(Finding(path, line_no, rule, shown.strip()[:120]))
    return findings


QUOTED_VALUE = re.compile(r"""(['"])([^'"\s]{8,})(['"])""")


def _redact_quoted_value(match_text: str, line: str) -> str:
    """Mask the quoted secret inside the line, keeping the variable name visible."""
    masked = QUOTED_VALUE.sub(lambda m: m.group(1) + redact(m.group(2)) + m.group(3), match_text)
    return line.replace(match_text, masked)


def scan_text(path: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(path, number, line))
    return findings


def scan_files(paths: Iterable[str]) -> List[Finding]:
    findings: List[Finding] = []
    for raw in paths:
        root = Path(raw)
        candidates = [root] if root.is_file() else _walk(root)
        for file_path in candidates:
            text = _read_text(file_path)
            if text is not None:
                findings.extend(scan_text(str(file_path), text))
    return findings


def scan_staged(repo: Optional[str] = None) -> List[Finding]:
    """Scan only the lines added in the staged diff (what the commit will contain)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACM"],
        capture_output=True, text=True, cwd=repo,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff failed")

    findings: List[Finding] = []
    current_file = ""
    new_line = 0
    for line in result.stdout.splitlines():
        if line.startswith("+++ "):
            current_file = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            match = HUNK.match(line)
            new_line = int(match.group("start")) if match else 0
        elif line.startswith("+") and not line.startswith("+++"):
            findings.extend(scan_line(current_file, new_line, line[1:]))
            new_line += 1
    return findings


def _walk(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in filenames:
            yield Path(dirpath, name)


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:1024]:
        return None  # binary file
    return raw.decode("utf-8", errors="ignore")
