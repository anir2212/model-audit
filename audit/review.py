"""Reviewer-side checks for saved audit bundles: integrity, plan drift and finding traces.

A bundle stores the status each test received under the plan in force when it ran. If
`configs/audit_plan.yaml` later changes, that stored status can be stale. These helpers
re-evaluate the saved measurements against the current plan so the console never shows
an old pass/warn/fail as if it were current.
"""
from __future__ import annotations

import hashlib
import json

from audit.registry import classify

FLAG_STATUSES = ("fail", "warn")


def finding_id(bundle: dict, test_id: str) -> str:
    """Stable identifier: one registered test can raise at most one finding per bundle."""
    return f"{bundle['dataset']}-{bundle['model']}-{test_id}"


def verify_digest(bundle: dict) -> bool:
    """Recompute the SHA-256 written by `audit.run.run_one` over the canonical body."""
    body = {key: value for key, value in bundle.items() if key != "sha256"}
    canonical = json.dumps(body, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest() == bundle.get("sha256")


def confirmation_scope(bundle: dict) -> dict:
    """Describe how independent the confirmation cohort is; none here is out-of-time."""
    source = bundle.get("confirmation_source", "")
    if "disjoint ID-proxy" in source:
        return {"kind": "disjoint_id_proxy", "independent_in_time": False,
                "label": "Disjoint rows selected by ID order. ID order is not a timestamp, so "
                         "this is a separate holdout, not out-of-time confirmation."}
    if "not an independent" in source:
        return {"kind": "reused_test_rows", "independent_in_time": False,
                "label": "Reuses 125 rows of the same test set. A reproduced flag here is not "
                         "independent confirmation."}
    return {"kind": "unclassified", "independent_in_time": False,
            "label": "Unrecognized confirmation source; treat it as not independent."}


def reevaluate(bundle: dict, plan: dict) -> list[dict]:
    """Compare every stored test status with its status under `plan`."""
    thresholds = plan["thresholds"]
    rows = []
    for test_id, test in bundle["tests"].items():
        stored_threshold, stored = test["threshold"], test["status"]
        current_threshold = thresholds.get(test_id)
        if current_threshold is None:
            current, reason = "information", "threshold removed" if stored_threshold else ""
        else:
            metric = current_threshold["metric"]
            value = test["values"].get(metric)
            if metric not in test["values"]:
                current, reason = "unmeasured", f"metric {metric!r} not in saved evidence"
            elif isinstance(value, bool) or not isinstance(value, (int, float)):
                current, reason = "unmeasured", f"metric {metric!r} is not a number"
            else:
                current = classify(test_id, test["values"][metric], plan)
                reason = ("threshold added after this run" if stored_threshold is None else
                          "threshold changed" if stored_threshold != current_threshold else "")
        if not reason and current != stored:
            reason = "status differs under current plan"
        rows.append({"test_id": test_id, "stored_status": stored, "current_status": current,
                     "stored_threshold": stored_threshold, "current_threshold": current_threshold,
                     "stale": bool(reason), "reason": reason})
    for test_id in thresholds:
        if test_id not in bundle["tests"]:
            rows.append({"test_id": test_id, "stored_status": "missing",
                         "current_status": "unmeasured", "stored_threshold": None,
                         "current_threshold": thresholds[test_id], "stale": True,
                         "reason": "registered test absent from this bundle"})
    return rows


def current_findings(bundle: dict, plan: dict) -> list[dict]:
    """Findings under the current plan, with confirmation recomputed where possible."""
    stored = {finding["test_id"]: finding for finding in bundle["findings"]}
    findings = []
    for row in reevaluate(bundle, plan):
        test_id = row["test_id"]
        if row["current_status"] not in FLAG_STATUSES and row["stored_status"] not in FLAG_STATUSES:
            continue
        test = bundle["tests"].get(test_id, {})
        threshold = row["current_threshold"]
        metric = threshold["metric"] if threshold else None
        old = stored.get(test_id, {})
        confirmation = old.get("confirmation", "not_run")
        if row["current_status"] in FLAG_STATUSES and "confirmation_value" in old:
            confirm_status = classify(test_id, old["confirmation_value"], plan)
            confirmation = "reproduced" if confirm_status in FLAG_STATUSES else "not_reproduced"
        elif row["current_status"] in FLAG_STATUSES:
            confirmation = "not_run_under_current_plan"
        else:
            confirmation = "cleared_under_current_plan"
        findings.append({
            "finding_id": finding_id(bundle, test_id), "test_id": test_id,
            "stored_status": row["stored_status"], "current_status": row["current_status"],
            "stale": row["stale"], "reason": row["reason"],
            "metric": metric, "observed": test.get("values", {}).get(metric),
            "confirmation": confirmation, "confirmation_value": old.get("confirmation_value")})
    return findings


def trace(bundle: dict, finding: dict, evidence_path: str, workpaper_path: str) -> dict:
    """Everything a reviewer needs to locate a finding's source evidence."""
    test = bundle["tests"][finding["test_id"]]
    return {"finding_id": finding["finding_id"], "test_id": finding["test_id"],
            "metric": finding["metric"], "observed": finding["observed"],
            "threshold": test["threshold"], "stored_status": finding["stored_status"],
            "current_status": finding["current_status"],
            "confirmation": finding["confirmation"],
            "confirmation_value": finding["confirmation_value"],
            "confirmation_source": bundle["confirmation_source"],
            "confirmation_scope": confirmation_scope(bundle)["label"],
            "test_cohort_rows": bundle["test_cohort_rows"],
            "evidence_file": evidence_path, "evidence_key": f"tests.{finding['test_id']}",
            "evidence_sha256": bundle["sha256"],
            "workpaper": f"{workpaper_path}#{finding['test_id']}"}
