"""YAML test registry with explicit local thresholds and severities."""
from __future__ import annotations

from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_plan(path=ROOT / "configs/audit_plan.yaml"):
    plan = yaml.safe_load(Path(path).read_text())
    if len(plan["thresholds"]) != len(set(plan["thresholds"])):
        raise ValueError("duplicate test id")
    return plan


def classify(test_id, value, plan):
    threshold = plan["thresholds"][test_id]
    if "fail_above" in threshold:
        return "fail" if value > threshold["fail_above"] else (
            "warn" if value > threshold["warn_above"] else "pass")
    return "fail" if value < threshold["fail_below"] else (
        "warn" if value < threshold["warn_below"] else "pass")
