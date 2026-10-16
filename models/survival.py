"""Retrospective time to first two-month delinquency from six UCI status fields."""
from __future__ import annotations

import json
import numpy as np
import pandas as pd
from lifelines import CoxPHFitter, KaplanMeierFitter
from lifelines.statistics import proportional_hazard_test
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

from models.data import ROOT, load_taiwan

PAY_ORDER = ["PAY_6", "PAY_5", "PAY_4", "PAY_3", "PAY_2", "PAY_0"]
BASELINE = ["LIMIT_BAL", "SEX", "AGE", "EDUCATION", "MARRIAGE"]


def make_person_level(features: pd.DataFrame):
    status = features[PAY_ORDER].to_numpy()
    event_month = status >= 2
    has_event = event_month.any(axis=1)
    duration = np.where(has_event, event_month.argmax(axis=1) + 1, 6)
    frame = features[BASELINE].copy()
    frame["duration"] = duration
    frame["event"] = has_event.astype(int)
    return frame


def make_person_month(person: pd.DataFrame):
    rows = []
    for idx, row in person.iterrows():
        for month in range(1, int(row["duration"]) + 1):
            rows.append((idx, month, int(row["event"] and month == row["duration"]),
                         float(row["LIMIT_BAL"]), int(row["AGE"])))
    return pd.DataFrame(rows, columns=["person_id", "month", "event", "limit_bal", "age"])


def run(max_people: int = 10000):
    features, _, provenance = load_taiwan()
    people = make_person_level(features.iloc[:max_people])
    fit = people.copy()
    fit["LIMIT_BAL"] /= 100000
    fit["AGE"] /= 10
    cox = CoxPHFitter(penalizer=0.1)
    cox.fit(fit, duration_col="duration", event_col="event")
    ph = proportional_hazard_test(cox, fit, time_transform="rank")
    km = {}
    for name, mask in (("limit_below_100k", people["LIMIT_BAL"] < 100000),
                       ("limit_at_least_100k", people["LIMIT_BAL"] >= 100000)):
        fitter = KaplanMeierFitter().fit(people.loc[mask, "duration"],
                                         people.loc[mask, "event"])
        km[name] = {"people": int(mask.sum()), "survival_at_3": float(fitter.predict(3)),
                    "survival_at_6": float(fitter.predict(6))}
    monthly = make_person_month(people)
    design = pd.get_dummies(monthly[["month", "limit_bal", "age"]].assign(
        month=monthly["month"].astype("category")), dtype=float)
    model = LogisticRegression(max_iter=500)
    model.fit(design, monthly["event"])
    hazard_auc = float(roc_auc_score(monthly["event"], model.predict_proba(design)[:, 1]))
    result = {"dataset": "UCI Taiwan; retrospective April–September payment statuses",
              "people": len(people), "person_month_rows": len(monthly),
              "event_definition": "first recorded payment delay of at least two months",
              "events": int(people["event"].sum()), "censored": int((people["event"] == 0).sum()),
              "cox_concordance_train": float(cox.concordance_index_),
              "cox_hazard_ratios": {name: float(value) for name, value in np.exp(cox.params_).items()},
              "ph_test_p": {name: float(value) for name, value in ph.summary["p"].items()},
              "kaplan_meier": km,
              "discrete_hazard_train_auc": hazard_auc,
              "warning": "Exploratory in-sample survival fit; event is delinquency proxy, not observed default. PH checks are diagnostics, not proof. Static default label is a different endpoint and later features can leak into early-event prediction."}
    out = ROOT / "runs/survival"
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(result, indent=2))
    monthly.to_csv(out / "person_month.csv", index=False)
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    run()
