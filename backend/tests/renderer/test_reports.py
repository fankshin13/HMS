"""3종 보고서 조판: 표 분할 방지 불변식, 감사 부록, 집계, PDF 생성."""

import io
import zipfile
from dataclasses import replace
from datetime import date
from decimal import Decimal
from xml.etree import ElementTree as etree

import pytest

from modules.renderer import analysis
from modules.renderer.docx_builder import build_docx
from modules.renderer.model import REPORT_TYPES, Code, Document
from modules.renderer.pdf_builder import build_pdf, to_html
from modules.renderer.reports import BUILDERS, SNIPPET_LINES, detailed, risk_plan
from tests.renderer.sample import sample

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _xml(docx: bytes) -> etree.Element:
    with zipfile.ZipFile(io.BytesIO(docx)) as archive:
        # 이 테스트가 방금 만든 문서만 읽는다(외부 입력 아님)
        return etree.fromstring(archive.read("word/document.xml"))  # noqa: S314


def _text(docx: bytes) -> str:
    return "".join(_xml(docx).itertext())


@pytest.fixture(scope="module")
def docs() -> dict[str, Document]:
    data = sample(3)
    return {kind: BUILDERS[kind](data) for kind in REPORT_TYPES}


@pytest.fixture(scope="module")
def docx_files(docs: dict[str, Document]) -> dict[str, bytes]:
    return {kind: build_docx(doc) for kind, doc in docs.items()}


@pytest.mark.parametrize("kind", REPORT_TYPES)
def test_every_table_row_cannot_split_and_headers_repeat(
    docx_files: dict[str, bytes], kind: str
) -> None:
    root = _xml(docx_files[kind])
    rows = root.iter(f"{W}tr")
    count = 0
    for row in rows:
        count += 1
        assert row.find(f"{W}trPr/{W}cantSplit") is not None
    assert count > 10
    for table in root.iter(f"{W}tbl"):
        first = table.find(f"{W}tr")
        assert first is not None
        if first.find(f"{W}trPr/{W}tblHeader") is not None:
            # 머리글 행 문단은 다음 행과 같은 페이지에 묶인다
            for paragraph in first.iter(f"{W}p"):
                assert paragraph.find(f"{W}pPr/{W}keepNext") is not None


def test_report_titles_and_korean_font(docx_files: dict[str, bytes]) -> None:
    assert "취약점 진단 상세 결과 보고서" in _text(docx_files["detailed"])
    assert "취약점 진단 결과 보고서" in _text(docx_files["summary"])
    assert "위험평가 결과 및 조치계획서" in _text(docx_files["risk_plan"])
    fonts = _xml(docx_files["summary"]).iter(f"{W}rFonts")
    assert any(f.get(f"{W}eastAsia") == "맑은 고딕" for f in fonts)


def test_detailed_report_lists_every_item_and_evidence(docx_files: dict[str, bytes]) -> None:
    text = _text(docx_files["detailed"])
    data = sample(3)
    for asset in data.assets:
        assert asset.hostname in text
        for item in asset.items:
            assert item.code in text
    assert "스크립트 원문 (" in text and "번째 줄" in text
    assert "조치 방법" in text


def test_long_snippets_are_truncated() -> None:
    data = sample(2)
    doc = detailed(data)
    codes = [b for b in doc.blocks if isinstance(b, Code)]
    assert codes
    for block in codes:
        assert len(block.text.splitlines()) <= SNIPPET_LINES + 1  # 생략 안내 한 줄 포함


def test_summary_has_charts_rankings_and_opinion(docs: dict[str, Document]) -> None:
    kinds = [type(b).__name__ for b in docs["summary"].blocks]
    assert kinds.count("Image") == 2
    text = _text(build_docx(docs["summary"]))
    assert "고위험 자산 순위" in text and "WIN-SRV-01" in text
    assert "양호율" in text and "7일 이내" in text


def test_risk_plan_appendix_contains_override_audit(docx_files: dict[str, bytes]) -> None:
    text = _text(docx_files["risk_plan"])
    assert "부록 A. 수동 판정 변경 감사 이력" in text
    assert "사내 보안 승인(SEC-2026-088)으로 예외" in text
    assert "홍길동 (owner@example.com)" in text
    assert "위험 매트릭스" in text and "조치 계획" in text


def test_risk_plan_without_overrides_says_so() -> None:
    data = replace(sample(2), overrides=[])
    text = _text(build_docx(risk_plan(data)))
    assert "판정 변경 이력이 없습니다" in text


def test_html_escapes_guideline_text(docs: dict[str, Document]) -> None:
    html = to_html(docs["detailed"])
    assert "양호 기준 &lt;원문&gt;" in html and "취약 기준 &amp; 원문" in html
    assert "<원문>" not in html


def test_pdf_is_generated(docs: dict[str, Document]) -> None:
    pdf = build_pdf(docs["summary"])
    assert pdf.startswith(b"%PDF") and len(pdf) > 10_000


# --- 집계 -----------------------------------------------------------------------------------


def test_totals_and_compliance_rate() -> None:
    data = sample(3)
    t = analysis.totals(data.assets, data.policy)
    assert t.checks == sum(len(a.items) for a in data.assets)
    assert t.good + t.vulnerable + t.na == t.checks
    assert t.critical + t.warning + t.caution == t.vulnerable
    expected = (Decimal(t.good) * 100 / (t.good + t.vulnerable)).quantize(Decimal("0.1"))
    assert t.compliance_rate == expected


def test_action_plan_due_dates_follow_risk_category() -> None:
    data = sample(2)
    today = date(2026, 11, 28)
    plan = analysis.action_plan(data.assets, data.policy, today)
    assert plan and plan == sorted(plan, key=lambda a: -a.item.score)
    for action in plan:
        days = {"critical": 7, "warning": 30, "caution": 90}[action.category]
        assert (action.due - today).days == days


def test_matrix_counts_vulnerable_items_by_importance_and_level() -> None:
    data = sample(3)
    cells = analysis.matrix(data.assets, data.policy)
    assert sum(cells.values()) == analysis.totals(data.assets, data.policy).vulnerable
    assert (9, "high") in cells and (6, "high") in cells
    assert analysis.matrix_score(9, "high", data.policy) == Decimal("27.00")
