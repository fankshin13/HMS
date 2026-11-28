"""요약 보고서 차트(PNG 바이트). 화면 없이 그리는 Agg 백엔드를 쓴다."""

import io
from functools import cache

import matplotlib

matplotlib.use("Agg")

from matplotlib import font_manager
from matplotlib import pyplot as plt
from matplotlib.figure import Figure

from modules.renderer.analysis import CategoryStat, Totals
from modules.renderer.fonts import FALLBACK_FAMILIES, FAMILY, font_files

# 인쇄 대비를 고려한 상태 색 (화면 디자인 토큰의 안전·경고·위험 계열)
GOOD = "#1E7F4F"
VULNERABLE = "#B42318"
NA = "#98A2B3"
TEXT = "#1D2939"


@cache
def _font_family() -> list[str]:
    """설치된 글꼴만 고른다(없는 이름을 넣으면 matplotlib 이 글자마다 경고를 남긴다)."""
    files = font_files()
    if files is not None:
        font_manager.fontManager.addfont(str(files.regular))
        font_manager.fontManager.addfont(str(files.bold))
    installed = {entry.name for entry in font_manager.fontManager.ttflist}
    families = [f for f in (FAMILY, *FALLBACK_FAMILIES) if f in installed]
    return families[:1] or ["DejaVu Sans"]


def _png(fig: Figure) -> bytes:
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    return buffer.getvalue()


def _style() -> None:
    plt.rcParams.update(
        {
            "font.family": _font_family(),
            "font.size": 9,
            "axes.edgecolor": "#D0D5DD",
            "axes.labelcolor": TEXT,
            "xtick.color": TEXT,
            "ytick.color": TEXT,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def status_donut(totals: Totals) -> bytes:
    """전체 판정 비율 도넛 차트."""
    _style()
    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    values = [totals.good, totals.vulnerable, totals.na]
    labels = [f"양호 {totals.good}", f"취약 {totals.vulnerable}", f"해당없음 {totals.na}"]
    if sum(values) == 0:
        values, labels = [1], ["결과 없음"]
    ax.pie(
        values,
        labels=labels,
        colors=[GOOD, VULNERABLE, NA][: len(values)],
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.38, "edgecolor": "white"},
        textprops={"color": TEXT},
    )
    ax.text(0, 0, f"양호율\n{totals.compliance_rate}%", ha="center", va="center", fontsize=11)
    ax.set_aspect("equal")
    return _png(fig)


def category_bars(stats: list[CategoryStat]) -> bytes:
    """분야별 양호·취약·해당없음 가로 누적 막대."""
    _style()
    fig, ax = plt.subplots(figsize=(6.4, 0.55 * max(len(stats), 1) + 1.0))
    labels = [s.label for s in stats]
    good = [s.good for s in stats]
    vulnerable = [s.vulnerable for s in stats]
    na = [s.na for s in stats]
    positions = range(len(stats))
    ax.barh(positions, vulnerable, color=VULNERABLE, label="취약")
    ax.barh(positions, good, left=vulnerable, color=GOOD, label="양호")
    ax.barh(
        positions,
        na,
        left=[v + g for v, g in zip(vulnerable, good, strict=True)],
        color=NA,
        label="해당없음",
    )
    for y, count in zip(positions, vulnerable, strict=True):
        if count:
            ax.text(count / 2, y, str(count), ha="center", va="center", color="white", fontsize=8)
    ax.set_yticks(list(positions), labels)
    ax.invert_yaxis()
    ax.set_xlabel("점검 항목 수")
    ax.legend(loc="lower right", frameon=False, ncols=3, bbox_to_anchor=(1, 1))
    return _png(fig)
