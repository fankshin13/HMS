"""보고서 조판 테스트용 표본 데이터: 실제 점검 결과 fixture 를 판정해 ReportData 로 만든다."""

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from modules.compliance.guideline_mapper import map_log
from modules.compliance.risk_evaluator import RiskPolicy, risk_score
from modules.parser.log_parser import parse_log
from modules.renderer.model import (
    AssetResult,
    ItemRow,
    OverrideRow,
    QuarantinedLog,
    ReportData,
    RiskLevel,
    RiskPolicyView,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
LEVELS: dict[str, RiskLevel] = {"U": "high", "W": "high"}
GENERATED = datetime(2026, 11, 28, 3, 0, tzinfo=UTC)


def _asset(name: str, hostname: str, cia: tuple[int, int, int]) -> AssetResult:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    mapped = map_log(parse_log(text))
    policy = RiskPolicy()
    items = []
    for r in mapped.results:
        level: RiskLevel = "medium" if r.item_code in ("U-66",) else "high"
        reason, _, evidence = r.stdout_snippet.partition("\n")
        items.append(
            ItemRow(
                code=r.item_code,
                name=f"{r.item_code} 점검 항목",
                category="account_management"
                if r.item_code in ("U-01", "U-02", "U-03", "U-04", "U-05", "U-06", "W-01", "W-02")
                else "service_management",
                risk_level=level,
                auto_status=r.status,
                final_status=r.status,
                score=risk_score(r.status, level, *cia, policy),
                reason=reason.removeprefix("[판정 근거] "),
                evidence=evidence,
                start_line=r.start_line,
                end_line=r.end_line,
                good_condition="양호 기준 <원문>",
                vulnerable_condition="취약 기준 & 원문",
                remediation="조치 방법 설명",
            )
        )
    os_type = "windows" if hostname.startswith("WIN") else "linux"
    return AssetResult(hostname, os_type, None, cia[0], cia[1], cia[2], items)


def sample(hosts: int = 3) -> ReportData:
    assets = [_asset("windows_default.txt", "WIN-SRV-01", (3, 3, 3))]
    for i in range(hosts - 1):
        assets.append(_asset("linux_ubuntu_default.txt", f"host-{i:02d}", (2, 2, 2)))
    return ReportData(
        organization="보안팀",
        run_title="2026 하반기 정기 진단",
        run_created_at=GENERATED,
        generated_at=GENERATED,
        policy=RiskPolicyView(),
        assets=assets,
        overrides=[
            OverrideRow(
                GENERATED,
                "host-00",
                "U-18",
                "/etc/shadow 권한",
                "vulnerable",
                "good",
                "사내 보안 승인(SEC-2026-088)으로 예외",
                "홍길동 (owner@example.com)",
            )
        ],
        quarantined=[QuarantinedLog("broken.txt", None, 1, ["표준 형식이 아닌 줄입니다"])],
    )


def score(value: str) -> Decimal:
    return Decimal(value)
