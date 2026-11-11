"""Fail if Git tracks or has staged a private key, a real sign-off log or a real allowlist.

`.gitignore` stops an ordinary `git add`, but not `git add -f`. This scans the index itself and
runs in `make test` and `make key-check`. It is a check to run, not an installed Git hook.

Usage: .venv/bin/python scripts/check_no_committed_keys.py [repository path]
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

MARKER = "BEGIN [A-Z0-9 ]*PRIVATE KEY"
RISKY_NAME = re.compile(r"(\.(pem|key|p8)$|private[_-]?key|_private|(^|/)signoffs\.jsonl$"
                        r"|^reviews/reviewer_keys\.json$)", re.IGNORECASE)


def problems(repository: Path) -> list[str]:
    """Tracked or staged paths that look like secrets, by name or by content in the index."""
    def git(*arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(repository), *arguments], capture_output=True, text=True)

    listed = git("ls-files", "--cached")
    if listed.returncode != 0:
        raise RuntimeError(f"not a Git repository: {repository}")
    found = [f"risky file name: {path}" for path in listed.stdout.splitlines() if RISKY_NAME.search(path)]
    found += [f"private key content: {path}" for path in
              git("grep", "--cached", "-l", "-E", MARKER).stdout.splitlines()]
    return found


def main() -> int:
    repository = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    found = problems(repository)
    for item in found:
        print(item, file=sys.stderr)
    if found:
        return 1
    print("No private key, sign-off log or reviewer allowlist is tracked or staged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
