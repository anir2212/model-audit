"""Run registered credit-model tests with evidence and independent-cohort checks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from audit.metrics import (auc_bootstrap, calibration, fairness_slices, ks_statistic,
                           population_stability, threshold_tradeoff)
from audit.registry import classify, load_plan
from models.data import ROOT, load_taiwan, load_german, split_taiwan, split_german


def _groups(dataset, features):
    if dataset == "taiwan":
        sex = features["SEX"].map({1: "male", 2: "female"}).fillna("unknown")
        age = np.where(features["AGE"] < 35, "under35", "35plus")
    else:
        sex = np.where(features["A09"].isin(["A92", "A95"]), "female", "male_or_other")
        age = np.where(features["A13"] < 35, "under35", "35plus")
    return sex, age


def _stress(dataset, features):
    stressed = features.copy()
    if dataset == "taiwan":
        stressed["LIMIT_BAL"] = stressed["LIMIT_BAL"] * 0.8
        stressed["AGE"] = stressed["AGE"] + 5
    else:
        stressed["A05"] = stressed["A05"] * 1.25
        stressed["A13"] = stressed["A13"] + 5
    return stressed


def _data_quality(dataset, features, labels):
    if dataset == "taiwan":
        invalid = int((~features["SEX"].isin([1, 2])).sum() +
                      (~features["EDUCATION"].isin([1, 2, 3, 4])).sum() +
                      (~features["MARRIAGE"].isin([1, 2, 3])).sum())
    else:
        invalid = int((~features["A09"].isin(["A91", "A92", "A93", "A94", "A95"])).sum())
    return {"rows": len(features), "null_cells": int(features.isna().sum().sum()),
            "duplicate_feature_rows": int(features.duplicated().sum()),
            "invalid_categories": invalid, "label_out_of_range": int((~labels.isin([0, 1])).sum()),
            "id_and_target_excluded": "ID" not in features and "default" not in features}


def _robustness(dataset, model, features):
    sample = features.iloc[:min(400, len(features))].copy()
    before = model.predict_proba(sample)[:, 1]
    if dataset == "taiwan":
        shifted = sample.copy(); shifted["PAY_0"] += 1
        missing = sample.copy(); missing.loc[missing.index[:10], "LIMIT_BAL"] = np.nan
    else:
        shifted = sample.copy(); shifted["A02"] += 6
        missing = sample.copy(); missing.loc[missing.index[:10], "A05"] = np.nan
    after = model.predict_proba(shifted)[:, 1]
    with_missing = model.predict_proba(missing)[:, 1]
    return {"test_feature": "PAY_0 missed-payment months" if dataset == "taiwan" else
            "A02 loan duration months (stress proxy)",
            "violations": int(np.sum(after < before - 1e-8)), "sample_rows": len(sample),
            "max_absolute_change": float(np.max(np.abs(after - before))),
            "missing_predictions_finite": bool(np.isfinite(with_missing).all())}


def _metrics(dataset, model, train_x, train_y, test_x, test_y):
    train_risk = model.predict_proba(train_x)[:, 1]
    risk = model.predict_proba(test_x)[:, 1]
    stressed = _stress(dataset, test_x)
    stressed_risk = model.predict_proba(stressed)[:, 1]
    sex, age = _groups(dataset, test_x)
    auc = float(roc_auc_score(test_y, risk))
    feature = "LIMIT_BAL" if dataset == "taiwan" else "A05"
    output = {
        "PERF-AUC-01": {"auc": auc, "auc_ci95": auc_bootstrap(test_y, risk),
                         "ks": ks_statistic(test_y, risk), "gini": 2 * auc - 1,
                         "count": len(test_y)},
        "CAL-ECE-01": calibration(test_y, risk),
        "STAB-PSI-01": {"psi": population_stability(train_risk, stressed_risk),
                         "baseline_test_psi": population_stability(train_risk, risk),
                         "scenario": "limit -20% and age +5" if dataset == "taiwan" else
                         "amount +25% and age +5"},
        "STAB-CSI-01": {"max_csi": population_stability(train_x[feature], stressed[feature]),
                         "feature": feature, "baseline_test_csi": population_stability(
                             train_x[feature], test_x[feature])},
        "FAIR-SEX-01": fairness_slices(test_y, risk, sex),
        "FAIR-AGE-01": fairness_slices(test_y, risk, age),
        "ROB-MONO-01": _robustness(dataset, model, test_x),
        "DQ-CAT-01": _data_quality(dataset, test_x, test_y),
        "FAIR-TRADEOFF": {"thresholds": threshold_tradeoff(test_y, risk, sex)},
    }
    return output


def run_one(dataset: str, model_name: str):
    features, labels, provenance = (load_taiwan() if dataset == "taiwan" else load_german())
    splits = (split_taiwan(features, labels) if dataset == "taiwan" else split_german(features, labels))
    train_x, train_y = splits["train"]
    test_x, test_y = splits["test"]
    model = joblib.load(ROOT / "runs/models" / dataset / f"{model_name}.joblib")
    plan = load_plan()
    metrics = _metrics(dataset, model, train_x, train_y, test_x, test_y)
    explain_path = ROOT / "runs/audit" / f"{dataset}_explain.json"
    if explain_path.exists():
        metrics["EXPL-SHAP-01"] = json.loads(explain_path.read_text())
    survival_path = ROOT / "runs/survival/results.json"
    if dataset == "taiwan" and survival_path.exists():
        metrics["SURV-01"] = json.loads(survival_path.read_text())
    tests = {}
    for test_id, values in metrics.items():
        if test_id in plan["thresholds"]:
            threshold = plan["thresholds"][test_id]
            metric = threshold["metric"]
            status = classify(test_id, values[metric], plan)
        else:
            threshold, status = None, "information"
        tests[test_id] = {"status": status, "values": values, "threshold": threshold}
    findings = [{"test_id": test_id, "severity": "high" if test["status"] == "fail" else "medium",
                 "observed": test["values"][test["threshold"]["metric"]],
                 "threshold": test["threshold"], "confirmation": "pending"}
                for test_id, test in tests.items() if test["status"] in ("fail", "warn")]
    if dataset == "taiwan":
        confirm_x, confirm_y = splits["validation"]
        confirm_source = "disjoint ID-proxy validation cohort (previous 6,000 rows)"
    else:
        confirm_x, confirm_y = test_x.iloc[:125], test_y.iloc[:125]
        confirm_source = "test subset; not an independent confirmation cohort"
    confirm_metrics = _metrics(dataset, model, train_x, train_y, confirm_x, confirm_y)
    for finding in findings:
        test_id = finding["test_id"]
        metric = plan["thresholds"][test_id]["metric"]
        confirmation_status = classify(test_id, confirm_metrics[test_id][metric], plan)
        finding["confirmation"] = "reproduced" if confirmation_status in ("fail", "warn") else "not_reproduced"
        finding["confirmation_value"] = confirm_metrics[test_id][metric]
    body = {"dataset": dataset, "model": model_name, "provenance": provenance,
            "audit_plan": "configs/audit_plan.yaml", "test_cohort_rows": len(test_x),
            "confirmation_source": confirm_source, "tests": tests, "findings": findings,
            "scope": "research demonstration only; thresholds are local review heuristics"}
    canonical = json.dumps(body, sort_keys=True, default=str)
    body["sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    output = ROOT / "runs/audit" / f"{dataset}_{model_name}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(body, indent=2, default=str))
    return body


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=("taiwan", "german", "all"), default="all")
    args = parser.parse_args()
    for dataset in (("taiwan", "german") if args.dataset == "all" else (args.dataset,)):
        for model in ("scorecard", "xgb"):
            result = run_one(dataset, model)
            print(dataset, model, "findings", len(result["findings"]),
                  {f["test_id"]: f["confirmation"] for f in result["findings"]})
