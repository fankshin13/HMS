"""위험 점수·등급 순수 함수."""

from decimal import Decimal

import pytest

from modules.compliance.risk_evaluator import (
    ItemStatus,
    RiskLevel,
    RiskPolicy,
    risk_category,
    risk_score,
)


def test_max_importance_high_level_is_27_and_critical() -> None:
    score = risk_score("vulnerable", "high", 3, 3, 3)
    assert score == Decimal("27.00")
    assert risk_category("vulnerable", score) == "critical"


@pytest.mark.parametrize(
    ("cia", "level", "expected"),
    [
        ((1, 1, 1), "low", "3.00"),
        ((2, 3, 2), "medium", "14.00"),
        ((2, 2, 1), "high", "15.00"),
        ((3, 3, 3), "low", "9.00"),
    ],
)
def test_score_is_importance_times_level(
    cia: tuple[int, int, int], level: RiskLevel, expected: str
) -> None:
    assert risk_score("vulnerable", level, *cia) == Decimal(expected)


@pytest.mark.parametrize("status", ["good", "na"])
def test_non_vulnerable_scores_zero_without_category(status: ItemStatus) -> None:
    score = risk_score(status, "high", 3, 3, 3)
    assert score == Decimal("0.00")
    assert risk_category(status, score) is None


@pytest.mark.parametrize(
    ("score", "category"),
    [("7.99", "caution"), ("8.00", "warning"), ("14.99", "warning"), ("15.00", "critical")],
)
def test_category_boundaries(score: str, category: str) -> None:
    assert risk_category("vulnerable", Decimal(score)) == category


def test_policy_weights_and_thresholds_apply() -> None:
    policy = RiskPolicy(
        confidentiality_weight=Decimal("2.00"), critical_threshold=20, warning_threshold=10
    )
    score = risk_score("vulnerable", "medium", 3, 1, 1, policy)
    assert score == Decimal("16.00")  # (3*2 + 1 + 1) * 2
    assert risk_category("vulnerable", score, policy) == "warning"


def test_rejects_out_of_range_importance() -> None:
    with pytest.raises(ValueError, match="1~3"):
        risk_score("vulnerable", "high", 4, 1, 1)
