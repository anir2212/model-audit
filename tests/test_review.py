import copy
import hashlib
import json

import pytest

from audit.registry import load_plan
from audit.review import (confirmation_scope, current_findings, finding_id, reevaluate, trace,
                          verify_digest)


def _bundle():
    body = {
        "dataset": "german", "model": "xgb", "test_cohort_rows": 250,
        "confirmation_source": "test subset; not an independent confirmation cohort",
        "tests": {
            "CAL-ECE-01": {"status": "warn", "values": {"ece": 0.042},
                           "threshold": {"metric": "ece", "warn_above": 0.03, "fail_above": 0.05}},
            "PERF-AUC-01": {"status": "pass", "values": {"auc": 0.80},
                            "threshold": {"metric": "auc", "warn_below": 0.75, "fail_below": 0.70}},
            "FAIR-TRADEOFF": {"status": "information", "values": {"thresholds": []}, "threshold": None},
        },
        "findings": [{"test_id": "CAL-ECE-01", "severity": "medium", "observed": 0.042,
                      "threshold": {"metric": "ece", "warn_above": 0.03, "fail_above": 0.05},
                      "confirmation": "reproduced", "confirmation_value": 0.067}],
    }
    body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    return body


def _plan(**changes):
    plan = {"thresholds": {
        "CAL-ECE-01": {"metric": "ece", "warn_above": 0.03, "fail_above": 0.05},
        "PERF-AUC-01": {"metric": "auc", "warn_below": 0.75, "fail_below": 0.70}}}
    plan["thresholds"].update(changes)
    return {"thresholds": {k: v for k, v in plan["thresholds"].items() if v is not None}}


def test_digest_detects_edited_evidence():
    bundle = _bundle()
    assert verify_digest(bundle)
    bundle["tests"]["CAL-ECE-01"]["values"]["ece"] = 0.01
    assert not verify_digest(bundle)


def test_unchanged_plan_reports_no_drift_and_same_findings():
    bundle = _bundle()
    assert not [row for row in reevaluate(bundle, _plan()) if row["stale"]]
    findings = current_findings(bundle, _plan())
    assert [(f["finding_id"], f["current_status"], f["confirmation"]) for f in findings] == [
        ("german-xgb-CAL-ECE-01", "warn", "reproduced")]


def test_changed_threshold_cannot_keep_old_status():
    plan = _plan(**{"CAL-ECE-01": {"metric": "ece", "warn_above": 0.08, "fail_above": 0.1}})
    row = next(r for r in reevaluate(_bundle(), plan) if r["test_id"] == "CAL-ECE-01")
    assert row["stale"] and row["stored_status"] == "warn" and row["current_status"] == "pass"
    assert row["reason"] == "threshold changed"
    finding = current_findings(_bundle(), plan)[0]
    assert finding["current_status"] == "pass" and finding["confirmation"] == "cleared_under_current_plan"


def test_tighter_threshold_raises_new_unconfirmed_finding():
    plan = _plan(**{"PERF-AUC-01": {"metric": "auc", "warn_below": 0.85, "fail_below": 0.70}})
    findings = {f["test_id"]: f for f in current_findings(_bundle(), plan)}
    assert findings["PERF-AUC-01"]["current_status"] == "warn"
    assert findings["PERF-AUC-01"]["stored_status"] == "pass"
    assert findings["PERF-AUC-01"]["confirmation"] == "not_run_under_current_plan"


def test_confirmation_is_recomputed_under_changed_plan():
    plan = _plan(**{"CAL-ECE-01": {"metric": "ece", "warn_above": 0.04, "fail_above": 0.07}})
    finding = current_findings(_bundle(), plan)[0]
    assert finding["current_status"] == "warn" and finding["confirmation"] == "reproduced"
    plan = _plan(**{"CAL-ECE-01": {"metric": "ece", "warn_above": 0.04, "fail_above": 0.2}})
    plan["thresholds"]["CAL-ECE-01"]["warn_above"] = 0.041
    bundle = _bundle()
    bundle["findings"][0]["confirmation_value"] = 0.035
    assert current_findings(bundle, plan)[0]["confirmation"] == "not_reproduced"


def test_added_removed_and_missing_thresholds_are_stale():
    added = _plan(**{"FAIR-TRADEOFF": {"metric": "thresholds", "warn_above": 0, "fail_above": 1}})
    row = next(r for r in reevaluate(_bundle(), added) if r["test_id"] == "FAIR-TRADEOFF")
    assert row["stale"] and row["current_status"] == "unmeasured" and "not a number" in row["reason"]
    numeric = _plan(**{"PERF-AUC-01": None})
    bundle = _bundle()
    bundle["tests"]["PERF-AUC-01"]["threshold"] = None
    bundle["tests"]["PERF-AUC-01"]["status"] = "information"
    numeric["thresholds"]["PERF-AUC-01"] = {"metric": "auc", "warn_below": 0.75, "fail_below": 0.70}
    row = next(r for r in reevaluate(bundle, numeric) if r["test_id"] == "PERF-AUC-01")
    assert row["reason"] == "threshold added after this run" and row["current_status"] == "pass"
    removed = next(r for r in reevaluate(_bundle(), _plan(**{"CAL-ECE-01": None}))
                   if r["test_id"] == "CAL-ECE-01")
    assert removed["stale"] and removed["current_status"] == "information"
    missing = _plan(**{"STAB-PSI-01": {"metric": "psi", "warn_above": 0.1, "fail_above": 0.25}})
    row = next(r for r in reevaluate(_bundle(), missing) if r["test_id"] == "STAB-PSI-01")
    assert row["stale"] and row["stored_status"] == "missing"
    renamed = _plan(**{"CAL-ECE-01": {"metric": "brier", "warn_above": 0.1, "fail_above": 0.2}})
    row = next(r for r in reevaluate(_bundle(), renamed) if r["test_id"] == "CAL-ECE-01")
    assert row["current_status"] == "unmeasured" and row["stale"]


def test_confirmation_scope_never_claims_time_independence():
    german = confirmation_scope(_bundle())
    assert german["kind"] == "reused_test_rows" and not german["independent_in_time"]
    taiwan = confirmation_scope({"confirmation_source":
                                 "disjoint ID-proxy validation cohort (previous 6,000 rows)"})
    assert taiwan["kind"] == "disjoint_id_proxy" and "not a timestamp" in taiwan["label"]
    assert confirmation_scope({})["kind"] == "unclassified"


def test_trace_points_to_evidence_and_workpaper_anchor():
    bundle = _bundle()
    finding = current_findings(bundle, _plan())[0]
    ref = trace(bundle, finding, "runs/audit/german_xgb.json", "runs/workpapers/german_xgb.html")
    assert ref["finding_id"] == finding_id(bundle, "CAL-ECE-01")
    assert ref["evidence_key"] == "tests.CAL-ECE-01" and ref["observed"] == 0.042
    assert ref["workpaper"].endswith("german_xgb.html#CAL-ECE-01")
    assert ref["evidence_sha256"] == bundle["sha256"]


@pytest.mark.parametrize("name", ["taiwan_scorecard", "taiwan_xgb", "german_scorecard", "german_xgb"])
def test_saved_evidence_is_intact_and_current_with_plan(name):
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    bundle = json.loads((root / "evidence/audit" / f"{name}.json").read_text())
    assert verify_digest(bundle)
    assert not [row for row in reevaluate(bundle, load_plan()) if row["stale"]]
    stored = {f["test_id"]: f["confirmation"] for f in bundle["findings"]}
    live = {f["test_id"]: f["confirmation"] for f in current_findings(bundle, load_plan())}
    assert stored == live
    html = (root / "evidence/workpapers" / f"{name}.html").read_text()
    for finding in bundle["findings"]:
        assert f'id="{finding["test_id"]}"' in html


def test_reevaluate_does_not_mutate_bundle():
    bundle = _bundle()
    before = copy.deepcopy(bundle)
    current_findings(bundle, _plan(**{"CAL-ECE-01": {"metric": "ece", "warn_above": 0.5, "fail_above": 0.6}}))
    assert bundle == before
