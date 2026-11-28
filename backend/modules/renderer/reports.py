"""3종 보고서 구성: ReportData → 중립 문서(Document).

1. 취약점 진단 상세 결과 보고서: 자산별 전수 점검 결과, 취약·변경 항목의 판정 근거·원문·조치 방법
2. 취약점 진단 결과 보고서: 경영진·관리자용 요약(판정 비율, 분야별 분포, 고위험 자산, 종합 의견)
3. 위험평가 결과 및 조치계획서: 위험 매트릭스, 자산별 위험도, 조치 일정표, 판정 변경 감사 부록
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from modules.renderer import analysis, charts
from modules.renderer.analysis import (
    ACTION_LABELS,
    CATEGORY_LABELS,
    CATEGORY_RISK_LABELS,
    RISK_LABELS,
    STATUS_LABELS,
)
from modules.renderer.model import (
    REPORT_TITLES,
    Block,
    Cell,
    Code,
    Cover,
    Document,
    Heading,
    Image,
    ItemRow,
    KeyValues,
    PageBreak,
    Paragraph,
    ReportData,
    ReportType,
    RiskCategory,
    Status,
    Table,
    Tone,
)

SEOUL = ZoneInfo("Asia/Seoul")
STANDARD = "KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」"
SNIPPET_LINES = 25

STATUS_TONES: dict[Status, Tone] = {"good": "safe", "vulnerable": "danger", "na": "muted"}
RISK_TONES: dict[RiskCategory, Tone] = {
    "critical": "danger",
    "warning": "warning",
    "caution": "muted",
}


def _date(value: datetime) -> str:
    return value.astimezone(SEOUL).strftime("%Y-%m-%d")


def _datetime(value: datetime) -> str:
    return value.astimezone(SEOUL).strftime("%Y-%m-%d %H:%M")


def _status(status: Status) -> Cell:
    return Cell(STATUS_LABELS[status], STATUS_TONES[status], bold=status == "vulnerable")


def _risk(item: ItemRow, data: ReportData) -> Cell:
    category = analysis.risk_category(item, data.policy)
    if category is None:
        return Cell("-", "muted")
    return Cell(f"{CATEGORY_RISK_LABELS[category]} {item.score:.2f}", RISK_TONES[category], True)


def _cover(kind: ReportType, data: ReportData, subtitle: str) -> Cover:
    return Cover(
        title=REPORT_TITLES[kind],
        subtitle=subtitle,
        meta=[
            ("기관", data.organization),
            ("진단명", data.run_title),
            ("진단 등록일", _date(data.run_created_at)),
            ("보고서 작성일", _date(data.generated_at)),
            ("진단 기준", STANDARD),
        ],
    )


def _snippet(evidence: str) -> str:
    lines = evidence.splitlines()
    if len(lines) <= SNIPPET_LINES:
        return evidence
    return "\n".join([*lines[:SNIPPET_LINES], f"… (이하 {len(lines) - SNIPPET_LINES}줄 생략)"])


def _overview(data: ReportData) -> list[Block]:
    t = analysis.totals(data.assets, data.policy)
    return [
        KeyValues(
            [
                ("진단 대상 자산", f"{t.assets}대"),
                ("점검 항목", f"{t.checks:,}건"),
                ("판정 결과", f"양호 {t.good:,} · 취약 {t.vulnerable:,} · 해당없음 {t.na:,}"),
                ("양호율", f"{t.compliance_rate}% (해당없음 제외)"),
                ("위험 등급", f"긴급 {t.critical} · 경고 {t.warning} · 주의 {t.caution}"),
                ("수동 검토 필요 로그", f"{len(data.quarantined)}건"),
            ]
        )
    ]


# --- 1. 상세 결과 보고서 -----------------------------------------------------------------------


def detailed(data: ReportData) -> Document:
    blocks: list[Block] = [
        _cover("detailed", data, "자산별 전수 점검 결과와 판정 근거"),
        PageBreak(),
        Heading("1. 진단 개요"),
        Paragraph(
            f"본 보고서는 {STANDARD}의 판단 기준에 따라 표준 점검 스크립트로 수집한 결과를 "
            "자동 판정하고, 담당자가 검토·변경한 최종 판정을 자산별로 정리한 것입니다."
        ),
        *_overview(data),
        Heading("2. 진단 대상 자산"),
        Table(
            ["호스트", "운영체제", "중요도(C·I·A)", "점검", "취약", "격리 오류"],
            [
                [
                    Cell(a.hostname, bold=True),
                    Cell(f"{a.os_type}{' ' + a.os_version if a.os_version else ''}"),
                    Cell(f"{a.confidentiality}·{a.integrity}·{a.availability} (={a.importance})"),
                    Cell(str(len(a.items))),
                    Cell(
                        str(sum(1 for i in a.items if i.final_status == "vulnerable")),
                        "danger",
                        True,
                    ),
                    Cell(str(a.quarantined_errors), "warning" if a.quarantined_errors else "muted"),
                ]
                for a in data.assets
            ],
            widths=[22, 22, 20, 10, 10, 12],
        ),
        Heading("3. 자산별 점검 결과"),
        Paragraph(
            "각 자산의 전 항목 판정을 표로 싣고, 취약 항목과 판정이 변경된 항목은 판정 근거, "
            f"스크립트 원문(최대 {SNIPPET_LINES}줄, 원본 파일 줄 번호 표시), 판단 기준, "
            "조치 방법을 이어서 싣습니다.",
            small=True,
        ),
    ]
    for index, asset in enumerate(data.assets, start=1):
        blocks.append(PageBreak())
        blocks.append(Heading(f"3.{index} {asset.hostname}", 2))
        blocks.append(
            Table(
                ["코드", "점검 항목", "분야", "중요도", "판정", "위험"],
                [
                    [
                        Cell(item.code),
                        Cell(item.name + (" (변경)" if item.overridden else "")),
                        Cell(CATEGORY_LABELS.get(item.category, item.category)),
                        Cell(RISK_LABELS[item.risk_level]),
                        _status(item.final_status),
                        _risk(item, data),
                    ]
                    for item in asset.items
                ],
                widths=[9, 40, 17, 8, 10, 14],
            )
        )
        for item in asset.items:
            if item.final_status != "vulnerable" and not item.overridden:
                continue
            blocks.append(Heading(f"{item.code} {item.name}", 3))
            judged = STATUS_LABELS[item.final_status]
            if item.overridden:
                judged += f" (자동 판정 {STATUS_LABELS[item.auto_status]}에서 변경)"
            lines = (
                f"{item.start_line}~{item.end_line}번째 줄"
                if item.start_line is not None
                else "줄 정보 없음"
            )
            blocks.append(
                KeyValues(
                    [
                        ("최종 판정", judged),
                        ("위험 점수", f"{item.score:.2f}"),
                        ("판정 근거", item.reason or "-"),
                        ("양호 기준", item.good_condition),
                        ("취약 기준", item.vulnerable_condition),
                        ("조치 방법", item.remediation),
                    ]
                )
            )
            if item.evidence.strip():
                blocks.append(Code(_snippet(item.evidence), f"스크립트 원문 ({lines})"))
    if data.quarantined:
        blocks += [
            PageBreak(),
            Heading("4. 수동 검토 필요(격리) 결과 파일"),
            _quarantine_table(data),
        ]
    return Document(REPORT_TITLES["detailed"], f"{data.organization} · {data.run_title}", blocks)


def _quarantine_table(data: ReportData) -> Table:
    return Table(
        ["결과 파일", "호스트", "오류", "주요 내용"],
        [
            [
                Cell(q.file_name),
                Cell(q.hostname or "식별 불가", "warning" if q.hostname is None else "plain"),
                Cell(str(q.error_count)),
                Cell(" / ".join(q.first_errors[:3]) or "-"),
            ]
            for q in data.quarantined
        ],
        widths=[25, 18, 8, 49],
    )


# --- 2. 진단 결과(요약) 보고서 ------------------------------------------------------------------


def summary(data: ReportData) -> Document:
    t = analysis.totals(data.assets, data.policy)
    stats = analysis.category_stats(data.assets)
    risks = analysis.asset_risks(data.assets, data.policy)
    frequent = analysis.frequent_vulnerabilities(data.assets)
    blocks: list[Block] = [
        _cover("summary", data, "경영진·관리자용 진단 결과 요약"),
        PageBreak(),
        Heading("1. 진단 결과 요약"),
        *_overview(data),
        Image(charts.status_donut(t), 9.0, "전체 판정 비율"),
        Heading("2. 분야별 취약 분포"),
        Table(
            ["분야", "점검", "양호", "취약", "해당없음", "양호율"],
            [
                [
                    Cell(s.label, bold=True),
                    Cell(str(s.checks)),
                    Cell(str(s.good), "safe"),
                    Cell(str(s.vulnerable), "danger", True),
                    Cell(str(s.na), "muted"),
                    Cell(_rate(s.good, s.vulnerable)),
                ]
                for s in stats
            ],
            widths=[30, 14, 14, 14, 14, 14],
        ),
        Image(charts.category_bars(stats), 15.0, "분야별 판정 분포"),
        Heading("3. 고위험 자산 순위"),
        Table(
            ["순위", "호스트", "중요도", "취약", "긴급", "경고", "주의", "위험 점수 합계"],
            [
                [
                    Cell(str(rank)),
                    Cell(r.asset.hostname, bold=True),
                    Cell(str(r.asset.importance)),
                    Cell(str(r.vulnerable), "danger"),
                    Cell(str(r.critical), "danger" if r.critical else "muted", r.critical > 0),
                    Cell(str(r.warning), "warning" if r.warning else "muted"),
                    Cell(str(r.caution), "muted"),
                    Cell(f"{r.total_score:.2f}", bold=True),
                ]
                for rank, r in enumerate(risks[:10], start=1)
            ],
            widths=[8, 24, 10, 10, 10, 10, 10, 18],
        ),
        Heading("4. 다수 자산에서 발견된 취약 항목"),
        Table(
            ["코드", "점검 항목", "중요도", "취약 자산 수"],
            [
                [
                    Cell(f.code),
                    Cell(f.name),
                    Cell(RISK_LABELS[f.risk_level]),
                    Cell(f"{f.hosts} / {t.assets}", "danger", True),
                ]
                for f in frequent
            ]
            or [[Cell("취약 항목이 없습니다", "muted"), Cell(""), Cell(""), Cell("")]],
            widths=[12, 58, 12, 18],
        ),
        Heading("5. 종합 의견"),
        *[Paragraph(line) for line in _opinion(data)],
    ]
    return Document(REPORT_TITLES["summary"], f"{data.organization} · {data.run_title}", blocks)


def _rate(good: int, vulnerable: int) -> str:
    judged = good + vulnerable
    return f"{good * 100 / judged:.1f}%" if judged else "-"


def _opinion(data: ReportData) -> list[str]:
    t = analysis.totals(data.assets, data.policy)
    stats = sorted(analysis.category_stats(data.assets), key=lambda s: -s.vulnerable)
    lines = [
        f"진단 대상 {t.assets}대에서 {t.checks:,}개 항목을 점검한 결과 취약 {t.vulnerable:,}건이 "
        f"확인되었으며, 양호율은 {t.compliance_rate}%입니다."
    ]
    if t.critical:
        lines.append(
            "자산 중요도와 취약 등급을 결합한 위험 점수가 "
            f"{data.policy.critical}점 이상인 긴급 항목 "
            f"{t.critical}건은 7일 이내 조치를 권고합니다."
        )
    if t.warning:
        lines.append(
            f"경고 항목 {t.warning}건은 30일 이내, "
            f"주의 항목 {t.caution}건은 90일 이내 조치를 권고합니다."
        )
    if stats and stats[0].vulnerable:
        lines.append(
            f"분야별로는 {stats[0].label}에서 취약 항목이 가장 많아({stats[0].vulnerable}건) "
            "해당 분야의 표준 설정 기준 수립과 일괄 적용이 효과적입니다."
        )
    if data.quarantined:
        lines.append(
            f"표준 형식과 다른 결과 파일 {len(data.quarantined)}건은 수동 검토가 필요하며, "
            "점검 스크립트를 다시 실행해 보완하기를 권고합니다."
        )
    lines.append("세부 조치 일정은 「위험평가 결과 및 조치계획서」를 참고하십시오.")
    return lines


# --- 3. 위험평가 결과 및 조치계획서 -------------------------------------------------------------


def risk_plan(data: ReportData) -> Document:
    p = data.policy
    cells = analysis.matrix(data.assets, p)
    importances = sorted({a.importance for a in data.assets}, reverse=True) or [9]
    today = data.generated_at.astimezone(SEOUL).date()
    actions = analysis.action_plan(data.assets, p, today)
    risks = analysis.asset_risks(data.assets, p)

    def matrix_cell(importance: int, level: str) -> Cell:
        score = analysis.matrix_score(importance, level, p)
        tone: Tone = (
            "danger" if score >= p.critical else "warning" if score >= p.warning else "muted"
        )
        count = cells.get((importance, level), 0)
        return Cell(f"{score:.0f}점 · {count}건", tone, count > 0)

    blocks: list[Block] = [
        _cover("risk_plan", data, "정량적 위험평가와 취약점 조치 계획"),
        PageBreak(),
        Heading("1. 위험평가 방법"),
        Paragraph(
            "위험 점수 = 자산 중요도 × 취약 등급 가중치. 자산 중요도는 기밀성·무결성·가용성 점수"
            f"(각 1~3점)에 가중치(기밀성 {p.weight_c}, 무결성 {p.weight_i}, 가용성 {p.weight_a})를 "
            "곱해 더한 값이며, 취약 등급 가중치는 KISA 중요도 상 3, 중 2, 하 1입니다. "
            "양호·해당없음 항목은 0점입니다."
        ),
        KeyValues(
            [
                ("긴급", f"{p.critical}점 이상 — {ACTION_LABELS['critical']} 조치"),
                (
                    "경고",
                    f"{p.warning}점 이상 {p.critical}점 미만 — {ACTION_LABELS['warning']} 조치",
                ),
                ("주의", f"{p.warning}점 미만 — {ACTION_LABELS['caution']} 조치"),
            ]
        ),
        Heading("2. 위험 매트릭스"),
        Paragraph(
            "행은 자산 중요도(기밀성+무결성+가용성), 열은 취약 등급입니다. "
            "칸마다 대표 위험 점수와 해당 취약 항목 수를 표시합니다.",
            small=True,
        ),
        Table(
            ["자산 중요도", "상 (×3)", "중 (×2)", "하 (×1)"],
            [
                [
                    Cell(str(imp), bold=True),
                    *(matrix_cell(imp, lv) for lv in ("high", "medium", "low")),
                ]
                for imp in importances
            ],
            widths=[22, 26, 26, 26],
        ),
        Heading("3. 자산별 위험도"),
        Table(
            ["호스트", "중요도(C·I·A)", "취약", "긴급", "경고", "주의", "최고 점수", "합계"],
            [
                [
                    Cell(r.asset.hostname, bold=True),
                    Cell(f"{r.asset.confidentiality}·{r.asset.integrity}·{r.asset.availability}"),
                    Cell(str(r.vulnerable)),
                    Cell(str(r.critical), "danger" if r.critical else "muted", r.critical > 0),
                    Cell(str(r.warning), "warning" if r.warning else "muted"),
                    Cell(str(r.caution), "muted"),
                    Cell(f"{r.max_score:.2f}"),
                    Cell(f"{r.total_score:.2f}", bold=True),
                ]
                for r in risks
            ],
            widths=[22, 16, 9, 9, 9, 9, 13, 13],
        ),
        PageBreak(),
        Heading("4. 조치 계획"),
        Paragraph(
            f"보고서 작성일({today.isoformat()}) 기준 위험 등급별 기한을 적용했습니다. "
            "담당자·완료일은 조치 후 기입합니다.",
            small=True,
        ),
        Table(
            ["순번", "등급", "점수", "호스트", "항목", "조치 방법", "기한", "담당"],
            [
                [
                    Cell(str(n)),
                    Cell(CATEGORY_RISK_LABELS[a.category], RISK_TONES[a.category], True),
                    Cell(f"{a.item.score:.2f}"),
                    Cell(a.hostname),
                    Cell(f"{a.item.code} {a.item.name}"),
                    Cell(_short(a.item.remediation)),
                    Cell(a.due.isoformat()),
                    Cell(""),
                ]
                for n, a in enumerate(actions, start=1)
            ]
            or [[Cell("조치가 필요한 취약 항목이 없습니다", "muted")] + [Cell("")] * 7],
            widths=[6, 7, 8, 13, 21, 23, 14, 8],
        ),
        PageBreak(),
        Heading("부록 A. 수동 판정 변경 감사 이력"),
        Paragraph(
            "자동 판정을 담당자가 변경한 내역입니다. 감사 기록은 수정·삭제할 수 없도록 보관됩니다.",
            small=True,
        ),
        Table(
            ["일시", "호스트", "항목", "변경 전", "변경 후", "변경 사유", "변경자"],
            [
                [
                    Cell(_datetime(o.created_at)),
                    Cell(o.hostname),
                    Cell(f"{o.code} {o.name}"),
                    _status(o.previous),
                    _status(o.new),
                    Cell(o.reason),
                    Cell(o.actor),
                ]
                for o in data.overrides
            ]
            or [[Cell("판정 변경 이력이 없습니다", "muted")] + [Cell("")] * 6],
            widths=[13, 12, 20, 8, 8, 27, 12],
        ),
    ]
    if data.quarantined:
        blocks += [Heading("부록 B. 수동 검토 필요(격리) 결과 파일"), _quarantine_table(data)]
    return Document(REPORT_TITLES["risk_plan"], f"{data.organization} · {data.run_title}", blocks)


def _short(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


BUILDERS = {"detailed": detailed, "summary": summary, "risk_plan": risk_plan}
