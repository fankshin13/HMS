"""정량적 위험 점수와 위험 등급 계산 (순수 함수).

위험 점수 = (기밀성*W_c + 무결성*W_i + 가용성*W_a) * 취약 등급 가중치(상 3, 중 2, 하 1)
판정이 '취약'이 아니면 0. 같은 공식이 DB 함수 private.compute_risk_score 에도 있으며
tests/db/test_risk.py 가 두 구현의 일치를 확인한다.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Literal

RiskLevel = Literal["high", "medium", "low"]
ItemStatus = Literal["good", "vulnerable", "na"]
RiskCategory = Literal["critical", "warning", "caution"]

LEVEL_WEIGHTS: dict[RiskLevel, int] = {"high": 3, "medium": 2, "low": 1}
CENT = Decimal("0.01")


@dataclass(frozen=True)
class RiskPolicy:
    confidentiality_weight: Decimal = Decimal("1.00")
    integrity_weight: Decimal = Decimal("1.00")
    availability_weight: Decimal = Decimal("1.00")
    critical_threshold: int = 15
    warning_threshold: int = 8


DEFAULT_POLICY = RiskPolicy()


def asset_importance(
    confidentiality: int, integrity: int, availability: int, policy: RiskPolicy = DEFAULT_POLICY
) -> Decimal:
    for score in (confidentiality, integrity, availability):
        if not 1 <= score <= 3:
            raise ValueError(f"자산 중요도 점수는 1~3 이어야 합니다: {score}")
    return (
        confidentiality * policy.confidentiality_weight
        + integrity * policy.integrity_weight
        + availability * policy.availability_weight
    )


def risk_score(
    status: ItemStatus,
    level: RiskLevel,
    confidentiality: int,
    integrity: int,
    availability: int,
    policy: RiskPolicy = DEFAULT_POLICY,
) -> Decimal:
    importance = asset_importance(confidentiality, integrity, availability, policy)
    if status != "vulnerable":
        return Decimal("0.00")
    return (importance * LEVEL_WEIGHTS[level]).quantize(CENT, rounding=ROUND_HALF_UP)


def risk_category(
    status: ItemStatus, score: Decimal, policy: RiskPolicy = DEFAULT_POLICY
) -> RiskCategory | None:
    """취약 항목의 위험 등급. 양호·해당없음은 등급이 없다(None)."""
    if status != "vulnerable":
        return None
    if score >= policy.critical_threshold:
        return "critical"
    if score >= policy.warning_threshold:
        return "warning"
    return "caution"
