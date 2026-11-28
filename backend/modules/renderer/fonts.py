"""보고서 글꼴.

REPORT_FONT_DIR 에 Pretendard-Regular.otf·Pretendard-Bold.otf 가 있으면 PDF·차트에 사용한다.
없으면 시스템 한글 글꼴(fontconfig)로 대체한다. DOCX 는 글꼴 파일을 넣지 않고 이름만 지정하므로
열어 보는 PC 에 Pretendard 가 없으면 맑은 고딕으로 표시된다.
"""

import os
from dataclasses import dataclass
from pathlib import Path

FAMILY = "Pretendard"
# DOCX 동아시아 글꼴(Windows 기본 한글 글꼴)
DOCX_EAST_ASIA = "맑은 고딕"
FALLBACK_FAMILIES = ("Noto Sans CJK KR", "Malgun Gothic", "NanumGothic", "WenQuanYi Zen Hei")


@dataclass(frozen=True)
class FontFiles:
    regular: Path
    bold: Path


def font_files() -> FontFiles | None:
    directory = os.environ.get("REPORT_FONT_DIR", "").strip()
    if not directory:
        return None
    regular = Path(directory) / "Pretendard-Regular.otf"
    bold = Path(directory) / "Pretendard-Bold.otf"
    if regular.is_file() and bold.is_file():
        return FontFiles(regular, bold)
    return None
