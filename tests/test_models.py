import numpy as np
import pandas as pd
from models.scorecard import WoEScorecard


def test_scorecard_points_follow_risk():
    x = pd.DataFrame({'missed': [0, 0, 1, 1, 2, 2, 3, 3],
                      'group': ['a', 'b'] * 4})
    y = pd.Series([0, 0, 0, 1, 0, 1, 1, 1])
    model = WoEScorecard(bins=3).fit(x, y)
    p = model.predict_proba(x)[:, 1]
    points = model.points(x)
    assert np.corrcoef(p, points)[0, 1] < -0.9
    assert model.reason_codes(x, 0, top=2)
