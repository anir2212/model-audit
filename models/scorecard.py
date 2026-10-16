"""Small transparent quantile/category WoE logistic scorecard with PDO scaling."""
from __future__ import annotations

import math
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression


class WoEScorecard:
    def __init__(self, bins: int = 5, pdo: float = 20, base_score: float = 600,
                 base_good_odds: float = 20):
        self.bins, self.pdo = bins, pdo
        self.base_score, self.base_good_odds = base_score, base_good_odds
        self.edges = {}
        self.maps = {}
        self.default_woe = {}
        self.model = LogisticRegression(max_iter=1000, C=0.5)

    def _bucket(self, series: pd.Series, name: str):
        if name in self.edges:
            return pd.cut(pd.to_numeric(series, errors="coerce"), bins=self.edges[name],
                          labels=False, include_lowest=True).astype("Int64").astype(str)
        return series.fillna("MISSING").astype(str)

    def fit(self, features: pd.DataFrame, labels: pd.Series):
        y = np.asarray(labels, dtype=int)
        for name in features:
            series = features[name]
            if pd.api.types.is_numeric_dtype(series) and series.nunique() > self.bins:
                quantiles = np.unique(np.quantile(series.dropna(), np.linspace(0, 1, self.bins + 1)))
                if len(quantiles) > 2:
                    quantiles[0], quantiles[-1] = -np.inf, np.inf
                    self.edges[name] = quantiles
            categories = self._bucket(series, name).to_numpy()
            total_good, total_bad = (y == 0).sum(), (y == 1).sum()
            mapping = {}
            for category in np.unique(categories):
                mask = categories == category
                good = int((y[mask] == 0).sum())
                bad = int((y[mask] == 1).sum())
                mapping[category] = float(math.log(((good + 0.5) / (total_good + 0.5 * len(np.unique(categories)))) /
                                                   ((bad + 0.5) / (total_bad + 0.5 * len(np.unique(categories))))))
            self.maps[name] = mapping
            self.default_woe[name] = 0.0
        self.columns = list(features.columns)
        self.model.fit(self.transform(features), y)
        return self

    def transform(self, features: pd.DataFrame):
        if list(features.columns) != self.columns:
            features = features[self.columns]
        data = {name: self._bucket(features[name], name).map(self.maps[name]).fillna(0.0).to_numpy()
                for name in self.columns}
        return pd.DataFrame(data, index=features.index)

    def predict_proba(self, features: pd.DataFrame):
        return self.model.predict_proba(self.transform(features))

    def points(self, features: pd.DataFrame):
        risk = np.clip(self.predict_proba(features)[:, 1], 1e-6, 1 - 1e-6)
        factor = self.pdo / math.log(2)
        return self.base_score + factor * (np.log((1 - risk) / risk) - math.log(self.base_good_odds))

    def reason_codes(self, features: pd.DataFrame, row: int, top: int = 3):
        encoded = self.transform(features.iloc[[row]]).iloc[0]
        contributions = {name: float(encoded[name] * coef)
                         for name, coef in zip(self.columns, self.model.coef_[0])}
        return sorted(contributions, key=contributions.get, reverse=True)[:top]
