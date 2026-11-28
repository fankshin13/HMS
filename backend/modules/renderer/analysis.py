"""보고서 공통 집계: 판정 통계, 분야별 분포, 위험 등급, 자산 순위, 조치 기한."""

from collections import Counter
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal

from modules.renderer.model import AssetResult, ItemRow, RiskCategory, RiskPolicyView

CATEGORY_LABELS = {
    "account_management": "계정 관리",
    "directory_file_management": "파일·디렉터리 관리",
    "service_management": "서비스 관리",
    "patch_management": "패치 관리",
    "log_management": "로그 관리",
    "security_management": "보안 관리",
}
STATUS_LABELS = {"good": "양호", "vulnerable": "취약", "na": "해당없음"}
RISK_LABELS = {"high": "상", "medium": "중", "low": "하"}
LEVEL_WEIGHTS = {"high": 3, "medium": 2, "low": 1}
CATEGORY_RISK_LABELS: dict[RiskCategory, str] = {
    "critical": "긴급",
    "warning": "경고",
    "caution": "주의",
}
# 위험 등급별 조치 기한(보고서 작성일 기준)
ACTION_DAYS: dict[RiskCategory, int] = {"critical": 7, "warning": 30, "caution": 90}
ACTION_LABELS: dict[RiskCategory, str] = {
    "critical": "즉시(7일 이내)",
    "warning": "단기(30일 이내)",
    "caution": "중기(90일 이내)",
}


def risk_category(item: ItemRow, policy: RiskPolicyView) -> RiskCategory | None:
    if item.final_status != "vulnerable":
        return None
    if item.score >= policy.critical:
        return "critical"
    if item.score >= policy.warning:
        return "warning"
    return "caution"


@dataclass(frozen=True)
class Totals:
    assets: int
    checks: int
    good: int
    vulnerable: int
    na: int
    critical: int
    warning: int
    caution: int

    @property
    def compliance_rate(self) -> Decimal:
        """양호율(%) = 양호 / (양호 + 취약). 해당없음은 제외."""
        judged = self.good + self.vulnerable
        if judged == 0:
            return Decimal("0.0")
        return (Decimal(self.good) * 100 / judged).quantize(Decimal("0.1"))


def totals(assets: list[AssetResult], policy: RiskPolicyView) -> Totals:
    status = Counter(item.final_status for a in assets for item in a.items)
    risk = Counter(risk_category(item, policy) for a in assets for item in a.items)
    return Totals(
        assets=len(assets),
        checks=sum(status.values()),
        good=status["good"],
        vulnerable=status["vulnerable"],
        na=status["na"],
        critical=risk["critical"],
        warning=risk["warning"],
        caution=risk["caution"],
    )


@dataclass(frozen=True)
class CategoryStat:
    category: str
    label: str
    checks: int
    good: int
    vulnerable: int
    na: int


def category_stats(assets: list[AssetResult]) -> list[CategoryStat]:
    counts: dict[str, Counter[str]] = {}
    for asset in assets:
        for item in asset.items:
            counts.setdefault(item.category, Counter())[item.final_status] += 1
    return [
        CategoryStat(
            category=key,
            label=label,
            checks=sum(counts.get(key, Counter()).values()),
            good=counts.get(key, Counter())["good"],
            vulnerable=counts.get(key, Counter())["vulnerable"],
            na=counts.get(key, Counter())["na"],
        )
        for key, label in CATEGORY_LABELS.items()
        if key in counts
    ]


@dataclass(frozen=True)
class AssetRisk:
    asset: AssetResult
    vulnerable: int
    critical: int
    warning: int
    caution: int
    total_score: Decimal
    max_score: Decimal


def asset_risks(assets: list[AssetResult], policy: RiskPolicyView) -> list[AssetRisk]:
    """위험 점수 합계가 높은 순(같으면 긴급 건수, 호스트명)."""
    result = []
    for asset in assets:
        cats = Counter(risk_category(i, policy) for i in asset.items)
        scores = [i.score for i in asset.items if i.final_status == "vulnerable"]
        result.append(
            AssetRisk(
                asset=asset,
                vulnerable=len(scores),
                critical=cats["critical"],
                warning=cats["warning"],
                caution=cats["caution"],
                total_score=sum(scores, Decimal("0")),
                max_score=max(scores, default=Decimal("0")),
            )
        )
    return sorted(result, key=lambda r: (-r.total_score, -r.critical, r.asset.hostname))


@dataclass(frozen=True)
class FrequentItem:
    code: str
    name: str
    risk_level: str
    hosts: int


def frequent_vulnerabilities(assets: list[AssetResult], limit: int = 10) -> list[FrequentItem]:
    hosts: Counter[str] = Counter()
    names: dict[str, tuple[str, str]] = {}
    for asset in assets:
        for item in asset.items:
            if item.final_status == "vulnerable":
                hosts[item.code] += 1
                names[item.code] = (item.name, item.risk_level)
    ordered = sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [FrequentItem(code, names[code][0], names[code][1], count) for code, count in ordered]


@dataclass(frozen=True)
class ActionItem:
    hostname: str
    item: ItemRow
    category: RiskCategory
    due: date


def action_plan(assets: list[AssetResult], policy: RiskPolicyView, today: date) -> list[ActionItem]:
    """취약 항목 조치 계획: 위험 점수 높은 순, 기한은 등급별 일수."""
    actions = []
    for asset in assets:
        for item in asset.items:
            category = risk_category(item, policy)
            if category is not None:
                due = today + timedelta(days=ACTION_DAYS[category])
                actions.append(ActionItem(asset.hostname, item, category, due))
    return sorted(actions, key=lambda a: (-a.item.score, a.item.code, a.hostname))


def matrix(assets: list[AssetResult], policy: RiskPolicyView) -> dict[tuple[int, str], int]:
    """(자산 중요도 합계 3~9, 취약 등급) → 취약 항목 수."""
    cells: Counter[tuple[int, str]] = Counter()
    for asset in assets:
        for item in asset.items:
            if item.final_status == "vulnerable":
                cells[(asset.importance, item.risk_level)] += 1
    return dict(cells)


def matrix_score(importance: int, level: str, policy: RiskPolicyView) -> Decimal:
    """가중치를 반영한 대표 점수(가중치가 모두 같을 때 중요도 합계 × 등급)."""
    weight = (policy.weight_c + policy.weight_i + policy.weight_a) / 3
    return (Decimal(importance) * weight * LEVEL_WEIGHTS[level]).quantize(Decimal("0.01"))
