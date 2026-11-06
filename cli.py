"""Command-line interface.

  keyguard scan [PATHS...]   scan files (default: current directory)
  keyguard staged            scan what is about to be committed
  keyguard install-hook      install a pre-commit hook in this repository
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .patterns import IGNORE_MARKER
from .scanner import Finding, scan_files, scan_staged

HOOK = """#!/bin/sh
# Installed by keyguard: blocks commits that contain secrets.
python3 -m keyguard staged || {
  echo ""
  echo "Commit blocked by keyguard. If this is a false positive, add '# keyguard: ignore' on that line."
  exit 1
}
"""


def _color(enabled: bool):
    def paint(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if enabled else text
    return paint


def report(findings: List[Finding], paint, scope: str) -> int:
    if not findings:
        print(paint("1;32", f"✓ keyguard: no secrets found in {scope}."))
        return 0

    print(paint("1;31", f"✗ keyguard: {len(findings)} secret(s) found in {scope}\n"))
    for f in findings:
        print(f"  {paint('1', f.path)}:{f.line}  {paint('31', f.rule.title)}")
        print(f"    {paint('2', f.snippet)}")
    print("")
    print("Remove the secret, rotate it (it may already be exposed), then commit again.")
    print(paint("2", f"False positive? Add '{IGNORE_MARKER}' on that line."))
    return 1


def install_hook(repo: Path, force: bool) -> int:
    git_dir = repo / ".git"
    if not git_dir.is_dir():
        print("error: no .git directory here. Run this inside a Git repository.", file=sys.stderr)
        return 1

    hooks = git_dir / "hooks"
    hooks.mkdir(exist_ok=True)
    target = hooks / "pre-commit"
    if target.exists() and not force:
        print(f"error: {target} already exists. Use --force to replace it.", file=sys.stderr)
        return 1

    target.write_text(HOOK, encoding="utf-8")
    os.chmod(target, 0o755)
    print(f"✓ pre-commit hook installed at {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyguard",
        description="Stop API keys and passwords from reaching your Git history.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan files for secrets")
    scan.add_argument("paths", nargs="*", default=["."])

    sub.add_parser("staged", help="scan staged changes (used by the pre-commit hook)")

    hook = sub.add_parser("install-hook", help="install a pre-commit hook")
    hook.add_argument("--force", action="store_true", help="overwrite an existing hook")
    hook.add_argument("--repo", default=".", help="repository path (default: current directory)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    paint = _color(sys.stdout.isatty() and "NO_COLOR" not in os.environ)

    if args.command == "scan":
        return report(scan_files(args.paths), paint, "files")

    if args.command == "staged":
        try:
            findings = scan_staged()
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return report(findings, paint, "staged changes")

    if args.command == "install-hook":
        return install_hook(Path(args.repo), args.force)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
