import pytest
from audit.metrics import ks_statistic, population_stability, fairness_slices


def test_ks_hand_example():
    assert ks_statistic([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0


def test_psi_identical_vs_shifted():
    expected = list(range(100))
    assert population_stability(expected, expected) == pytest.approx(0)
    assert population_stability(expected, [v + 40 for v in expected]) > 0.1


def test_fairness_hand_example():
    metrics = fairness_slices([0, 0, 0, 0], [0.1, 0.2, 0.8, 0.9], ['a', 'a', 'b', 'b'], threshold=0.5)
    assert metrics['demographic_parity_difference'] == 1.0
    assert metrics['equalized_odds_difference'] == 1.0
