"""Global tree SHAP and scorecard adverse-factor stability diagnostics."""
from __future__ import annotations

import json
import joblib
import numpy as np
import xgboost as xgb

from models.data import ROOT, load_taiwan, load_german, split_taiwan, split_german


def run(dataset: str, sample_size: int = 100):
    features, labels, _ = (load_taiwan() if dataset == "taiwan" else load_german())
    splits = (split_taiwan(features, labels) if dataset == "taiwan" else split_german(features, labels))
    test_x, _ = splits["test"]
    sample = test_x.iloc[:sample_size].copy()
    base = ROOT / "runs/models" / dataset
    scorecard = joblib.load(base / "scorecard.joblib")
    xgb_model = joblib.load(base / "xgb.joblib")
    transformed = xgb_model.named_steps["features"].transform(sample)
    if hasattr(transformed, "toarray"):
        transformed = transformed.toarray()
    transformed = np.asarray(transformed, dtype=float)
    tree = xgb_model.named_steps["xgb"]
    # XGBoost's pred_contribs implements TreeSHAP and handles its current base_score format.
    shap_values = np.asarray(tree.get_booster().predict(
        xgb.DMatrix(transformed), pred_contribs=True))[:, :-1]
    names = list(xgb_model.named_steps["features"].get_feature_names_out())
    importance = np.mean(np.abs(shap_values), axis=0)
    global_top = sorted(zip(names, importance), key=lambda x: x[1], reverse=True)[:10]
    adverse = sorted(zip(names, shap_values[0]), key=lambda x: x[1], reverse=True)[:3]
    perturbed = sample.copy()
    field = "LIMIT_BAL" if dataset == "taiwan" else "A05"
    perturbed[field] *= 1.01
    original_reasons = [scorecard.reason_codes(sample, i) for i in range(len(sample))]
    altered_reasons = [scorecard.reason_codes(perturbed, i) for i in range(len(sample))]
    top3_overlap = float(np.mean([len(set(a) & set(b)) / 3 for a, b in
                                  zip(original_reasons, altered_reasons)]))
    result = {"dataset": dataset, "rows_explained": len(sample),
              "xgb_shap_global_top10": [{"feature": name, "mean_abs_shap": float(value)}
                                        for name, value in global_top],
              "xgb_first_case_adverse_top3": [{"feature": name, "shap_log_odds": float(value)}
                                               for name, value in adverse],
              "scorecard_first_case_reason_codes": original_reasons[0],
              "scorecard_top3_overlap_under_1pct_amount_change": top3_overlap,
              "warning": "SHAP is model explanation in log-odds space, not a causal reason or lawful adverse-action notice."}
    output = ROOT / "runs/audit" / f"{dataset}_explain.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    print(dataset, "SHAP top", global_top[0], "reason overlap", top3_overlap)
    return result


if __name__ == "__main__":
    for name in ("taiwan", "german"):
        run(name)
