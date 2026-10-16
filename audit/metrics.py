"""Auditable metric implementations used by the test registry."""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import chi2
from sklearn.metrics import roc_auc_score, roc_curve, brier_score_loss
from fairlearn.metrics import (demographic_parity_difference, equalized_odds_difference,
                               selection_rate, MetricFrame, true_positive_rate)


def ks_statistic(labels, risks):
    fpr, tpr, _ = roc_curve(labels, risks)
    return float(np.max(np.abs(tpr - fpr)))


def auc_bootstrap(labels, risks, seed=19, repeats=400):
    y, score = np.asarray(labels), np.asarray(risks)
    rng = np.random.default_rng(seed)
    estimates = []
    for _ in range(repeats):
        chosen = rng.integers(0, len(y), len(y))
        if len(np.unique(y[chosen])) == 2:
            estimates.append(roc_auc_score(y[chosen], score[chosen]))
    return [float(np.quantile(estimates, 0.025)), float(np.quantile(estimates, 0.975))]


def population_stability(expected, actual, bins=10):
    expected, actual = np.asarray(expected), np.asarray(actual)
    if not len(expected) or not len(actual):
        raise ValueError("nonempty distributions required")
    edges = np.unique(np.quantile(expected, np.linspace(0, 1, bins + 1)))
    if len(edges) < 3:
        return 0.0
    edges[0], edges[-1] = -np.inf, np.inf
    e = np.histogram(expected, bins=edges)[0] / len(expected)
    a = np.histogram(actual, bins=edges)[0] / len(actual)
    e, a = np.clip(e, 1e-6, None), np.clip(a, 1e-6, None)
    return float(np.sum((a - e) * np.log(a / e)))


def calibration(labels, risks, bins=10):
    y, p = np.asarray(labels), np.asarray(risks)
    groups = pd.qcut(p, q=bins, labels=False, duplicates="drop")
    rows = []
    statistic, ece = 0.0, 0.0
    for group in sorted(np.unique(groups)):
        mask = groups == group
        observed, expected = float(y[mask].sum()), float(p[mask].sum())
        n = int(mask.sum())
        rate, mean = observed / n, expected / n
        statistic += (observed - expected) ** 2 / max(expected * (1 - mean), 1e-8)
        ece += n / len(y) * abs(rate - mean)
        rows.append({"bin": int(group), "count": n, "observed_rate": rate,
                     "predicted_rate": mean})
    dof = max(1, len(rows) - 2)
    return {"brier": float(brier_score_loss(y, p)), "ece": float(ece),
            "calibration_in_the_large": float(np.mean(y) - np.mean(p)),
            "hosmer_lemeshow_stat": float(statistic), "hosmer_lemeshow_df": dof,
            "hosmer_lemeshow_p": float(chi2.sf(statistic, dof)), "reliability_bins": rows}


def fairness_slices(default_labels, risks, groups, threshold=0.25):
    good = 1 - np.asarray(default_labels)
    approved = (np.asarray(risks) < threshold).astype(int)
    groups = np.asarray(groups).astype(str)
    frame = MetricFrame(metrics={"approval_rate": selection_rate,
                                 "good_outcome_tpr": true_positive_rate},
                        y_true=good, y_pred=approved, sensitive_features=groups)
    by_group = {str(group): {name: None if pd.isna(value) else float(value)
                             for name, value in row.items()}
                for group, row in frame.by_group.iterrows()}
    rates = [v["approval_rate"] for v in by_group.values()]
    return {"threshold": threshold, "groups": by_group,
            "demographic_parity_difference": float(demographic_parity_difference(
                good, approved, sensitive_features=groups)),
            "equalized_odds_difference": float(equalized_odds_difference(
                good, approved, sensitive_features=groups)),
            "approval_rate_ratio": float(min(rates) / max(rates)) if max(rates) else None,
            "overall_approval_rate": float(np.mean(approved)),
            "approved_observed_default_rate": float(np.mean(np.asarray(default_labels)[approved == 1]))
                if approved.sum() else None}


def threshold_tradeoff(labels, risks, groups, thresholds=(0.15, 0.2, 0.25, 0.3, 0.35)):
    return [fairness_slices(labels, risks, groups, threshold) for threshold in thresholds]
