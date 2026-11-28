"""보고서 조판 입력(DTO)과 중립 문서 모델.

조판 코어는 DB 를 직접 조회하지 않는다. 워커의 서비스 계층이 ReportData 를 채워 넘기면,
보고서 구성(reports.py)이 문서 블록 목록을 만들고, DOCX·PDF 출력기가 같은 블록을 각자 그린다.
"""

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Literal

Status = Literal["good", "vulnerable", "na"]
RiskLevel = Literal["high", "medium", "low"]
RiskCategory = Literal["critical", "warning", "caution"]
ReportType = Literal["detailed", "summary", "risk_plan"]

REPORT_TYPES: tuple[ReportType, ...] = ("detailed", "summary", "risk_plan")
REPORT_TITLES: dict[ReportType, str] = {
    "detailed": "취약점 진단 상세 결과 보고서",
    "summary": "취약점 진단 결과 보고서",
    "risk_plan": "위험평가 결과 및 조치계획서",
}


# --- 입력 DTO ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class ItemRow:
    code: str
    name: str
    category: str
    risk_level: RiskLevel
    auto_status: Status
    final_status: Status
    score: Decimal
    reason: str
    evidence: str
    start_line: int | None
    end_line: int | None
    good_condition: str
    vulnerable_condition: str
    remediation: str
    overridden: bool = False


@dataclass(frozen=True)
class AssetResult:
    hostname: str
    os_type: str
    os_version: str | None
    confidentiality: int
    integrity: int
    availability: int
    items: list[ItemRow]
    quarantined_errors: int = 0

    @property
    def importance(self) -> int:
        return self.confidentiality + self.integrity + self.availability


@dataclass(frozen=True)
class OverrideRow:
    created_at: datetime
    hostname: str
    code: str
    name: str
    previous: Status
    new: Status
    reason: str
    actor: str


@dataclass(frozen=True)
class QuarantinedLog:
    file_name: str
    hostname: str | None
    error_count: int
    first_errors: list[str]


@dataclass(frozen=True)
class RiskPolicyView:
    critical: int = 15
    warning: int = 8
    weight_c: Decimal = Decimal("1.00")
    weight_i: Decimal = Decimal("1.00")
    weight_a: Decimal = Decimal("1.00")


@dataclass(frozen=True)
class ReportData:
    organization: str
    run_title: str
    run_created_at: datetime
    generated_at: datetime
    policy: RiskPolicyView
    assets: list[AssetResult]
    overrides: list[OverrideRow] = field(default_factory=list)
    quarantined: list[QuarantinedLog] = field(default_factory=list)


# --- 중립 문서 블록 ----------------------------------------------------------------------------

Tone = Literal["danger", "warning", "muted", "safe", "plain"]


@dataclass(frozen=True)
class Cell:
    text: str
    tone: Tone = "plain"
    bold: bool = False


@dataclass(frozen=True)
class Heading:
    text: str
    level: Literal[1, 2, 3] = 1


@dataclass(frozen=True)
class Paragraph:
    text: str
    tone: Tone = "plain"
    small: bool = False


@dataclass(frozen=True)
class Table:
    headers: list[str]
    rows: list[list[Cell]]
    # 열 너비 비율(합계 무관). 비우면 균등.
    widths: list[int] = field(default_factory=list)
    caption: str | None = None


@dataclass(frozen=True)
class KeyValues:
    pairs: list[tuple[str, str]]


@dataclass(frozen=True)
class Code:
    text: str
    caption: str | None = None


@dataclass(frozen=True)
class Image:
    png: bytes
    width_cm: float
    caption: str | None = None


@dataclass(frozen=True)
class PageBreak:
    pass


@dataclass(frozen=True)
class Cover:
    title: str
    subtitle: str
    meta: list[tuple[str, str]]


Block = Heading | Paragraph | Table | KeyValues | Code | Image | PageBreak | Cover


@dataclass(frozen=True)
class Document:
    title: str
    header: str
    blocks: list[Block]
