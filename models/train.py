"""Fit scorecard champion and XGBoost challenger; save local evidence."""
from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, brier_score_loss
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from xgboost import XGBClassifier

from models.data import ROOT, load_taiwan, load_german, split_taiwan, split_german
from models.scorecard import WoEScorecard


def _challenger(features):
    numeric = list(features.select_dtypes(include="number").columns)
    categorical = [name for name in features if name not in numeric]
    transformer = ColumnTransformer([
        ("num", SimpleImputer(strategy="median"), numeric),
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical)])
    return Pipeline([("features", transformer),
                     ("xgb", XGBClassifier(n_estimators=100, max_depth=3, learning_rate=0.05,
                                           subsample=0.9, colsample_bytree=0.9,
                                           objective="binary:logistic", eval_metric="logloss",
                                           n_jobs=2, random_state=7))])


def train_one(dataset: str):
    features, labels, provenance = (load_taiwan() if dataset == "taiwan" else load_german())
    splits = (split_taiwan(features, labels) if dataset == "taiwan" else split_german(features, labels))
    train_x, train_y = splits["train"]
    test_x, test_y = splits["test"]
    champion = WoEScorecard().fit(train_x, train_y)
    challenger = _challenger(train_x).fit(train_x, train_y)
    out = ROOT / "runs/models" / dataset
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(champion, out / "scorecard.joblib")
    joblib.dump(challenger, out / "xgb.joblib")
    scores = {}
    for name, model in (("scorecard", champion), ("xgb", challenger)):
        risk = model.predict_proba(test_x)[:, 1]
        scores[name] = {"auc": float(roc_auc_score(test_y, risk)),
                        "brier": float(brier_score_loss(test_y, risk)),
                        "risk_mean": float(np.mean(risk))}
        pd.DataFrame({"row_index": test_x.index, "label": test_y.to_numpy(), "risk": risk}).to_csv(
            out / f"{name}_test_predictions.csv", index=False)
    result = {"dataset": dataset, "provenance": provenance,
              "split_sizes": {key: len(value[0]) for key, value in splits.items()},
              "test_default_rate": float(np.mean(test_y)), "test_metrics": scores,
              "models": {"scorecard": "quantile/category WoE logistic with PDO points",
                         "xgb": "XGBClassifier, 100 trees, depth 3"}}
    (out / "training.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    for dataset in ("taiwan", "german"):
        print(json.dumps(train_one(dataset), indent=2))
