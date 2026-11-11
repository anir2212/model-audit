"""Local file locations shared by the console and the sign-off command.

Each path can be overridden with an environment variable so tests and reviewers can point
the tools at copies without touching the generated `runs/` folder or the real sign-off log.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = {
    "audit": ("MODELAUDIT_AUDIT_DIR", ROOT / "runs/audit"),
    "plan": ("MODELAUDIT_PLAN", ROOT / "configs/audit_plan.yaml"),
    "workpapers": ("MODELAUDIT_WORKPAPER_DIR", ROOT / "runs/workpapers"),
    "raw": ("MODELAUDIT_RAW_DIR", ROOT / "data/raw"),
    "signoff_log": ("MODELAUDIT_SIGNOFF_LOG", ROOT / "reviews/signoffs.jsonl"),
    "reviewer_keys": ("MODELAUDIT_REVIEWER_KEYS", ROOT / "reviews/reviewer_keys.json"),
}


def resolve() -> dict[str, Path]:
    result = {key: Path(os.environ.get(variable, default)) for key, (variable, default) in DEFAULTS.items()}
    anchor = os.environ.get("MODELAUDIT_SIGNOFF_ANCHOR")
    if anchor:
        result["signoff_anchor"] = Path(anchor)
    return result


def require_signature() -> bool:
    """True when `MODELAUDIT_REQUIRE_SIGNATURE` is set to anything but an explicit off value."""
    value = os.environ.get("MODELAUDIT_REQUIRE_SIGNATURE", "").strip().lower()
    return value not in {"", "0", "false", "no", "off"}
