"""중립 문서 → PDF (HTML + CSS Paged Media → WeasyPrint).

표 머리글은 페이지마다 반복되고, 행은 페이지 경계에서 쪼개지지 않는다(page-break-inside: avoid).
"""

import base64
from html import escape

from weasyprint import HTML

from modules.renderer.fonts import FALLBACK_FAMILIES, FAMILY, font_files
from modules.renderer.model import (
    Cell,
    Code,
    Cover,
    Document,
    Heading,
    Image,
    KeyValues,
    PageBreak,
    Paragraph,
    Table,
)

CSS = """
@page {
  size: A4;
  margin: 20mm 18mm 18mm;
  @top-right { content: "%(header)s"; font-size: 7.5pt; color: #667085; }
  @bottom-center { content: counter(page) " / " counter(pages); font-size: 8pt; color: #667085; }
}
@page cover { @top-right { content: none; } @bottom-center { content: none; } }
html { font-family: %(families)s; font-size: 9.5pt; color: #1D2939; line-height: 1.5; }
.cover { page: cover; padding-top: 70mm; text-align: center; }
.cover h1 { font-size: 24pt; margin: 0 0 6mm; }
.cover .sub { color: #667085; font-size: 12pt; margin-bottom: 30mm; }
.cover table { text-align: left; }
h1 { font-size: 15pt; margin: 8mm 0 3mm; }
h2 { font-size: 12.5pt; margin: 6mm 0 2.5mm; }
h3 { font-size: 10.5pt; margin: 4mm 0 2mm; }
h1, h2, h3 { break-after: avoid; }
p { margin: 0 0 2.5mm; }
p.small { font-size: 8pt; color: #667085; }
.break { break-after: page; }
table { width: 100%%; border-collapse: collapse; margin: 1mm 0 4mm; table-layout: fixed; }
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }
th, td { border: 0.6pt solid #C9CED6; padding: 1.4mm 1.8mm; vertical-align: top;
         overflow-wrap: anywhere; font-size: 8pt; }
th { background: #EEF1F5; text-align: left; font-weight: 700; }
table.kv th { width: 34mm; }
.danger { color: #B42318; } .warning { color: #B54708; } .safe { color: #1E7F4F; }
.muted { color: #667085; } .bold { font-weight: 700; }
pre { background: #F4F5F7; padding: 2mm 3mm; font-family: "DejaVu Sans Mono", monospace;
      font-size: 7pt; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0 0 4mm; }
.caption { font-size: 7.5pt; color: #667085; margin: 0 0 1mm; break-after: avoid; }
figure { margin: 2mm 0 5mm; text-align: center; break-inside: avoid; }
figure img { max-width: 100%%; }
"""


def _font_faces() -> str:
    files = font_files()
    if files is None:
        return ""
    return (
        f"@font-face {{ font-family: '{FAMILY}'; src: url('{files.regular.as_uri()}'); "
        "font-weight: 400; }\n"
        f"@font-face {{ font-family: '{FAMILY}'; src: url('{files.bold.as_uri()}'); "
        "font-weight: 700; }\n"
    )


def _cell(tag: str, cell: Cell) -> str:
    classes = " ".join(
        c for c in (cell.tone if cell.tone != "plain" else "", "bold" if cell.bold else "") if c
    )
    text = escape(cell.text).replace("\n", "<br>")
    return f'<{tag} class="{classes}">{text}</{tag}>' if classes else f"<{tag}>{text}</{tag}>"


def _table(block: Table) -> str:
    widths = block.widths or [1] * len(block.headers)
    total = sum(widths)
    cols = "".join(f'<col style="width:{w * 100 / total:.2f}%">' for w in widths)
    head = "".join(f"<th>{escape(h)}</th>" for h in block.headers)
    body = "".join(
        "<tr>" + "".join(_cell("td", c) for c in row[: len(block.headers)]) + "</tr>"
        for row in block.rows
    )
    caption = f'<p class="small">{escape(block.caption)}</p>' if block.caption else ""
    return (
        f"<table><colgroup>{cols}</colgroup><thead><tr>{head}</tr></thead>"
        f"<tbody>{body}</tbody></table>{caption}"
    )


def _key_values(block: KeyValues) -> str:
    rows = "".join(
        f"<tr><th>{escape(k)}</th><td>{escape(v).replace(chr(10), '<br>')}</td></tr>"
        for k, v in block.pairs
    )
    return f'<table class="kv"><tbody>{rows}</tbody></table>'


def to_html(doc: Document) -> str:
    families = ", ".join(f"'{f}'" for f in (FAMILY, *FALLBACK_FAMILIES)) + ", sans-serif"
    css = _font_faces() + CSS % {"header": doc.header.replace('"', "'"), "families": families}
    parts: list[str] = []
    for block in doc.blocks:
        match block:
            case Cover():
                parts.append(
                    f'<section class="cover"><h1>{escape(block.title)}</h1>'
                    f'<div class="sub">{escape(block.subtitle)}</div>'
                    f"{_key_values(KeyValues(block.meta))}</section>"
                )
            case Heading():
                parts.append(f"<h{block.level}>{escape(block.text)}</h{block.level}>")
            case Paragraph():
                css_class = " ".join(
                    c
                    for c in (
                        "small" if block.small else "",
                        block.tone if block.tone != "plain" else "",
                    )
                    if c
                )
                parts.append(f'<p class="{css_class}">{escape(block.text)}</p>')
            case Table():
                parts.append(_table(block))
            case KeyValues():
                parts.append(_key_values(block))
            case Code():
                caption = f'<p class="caption">{escape(block.caption)}</p>' if block.caption else ""
                parts.append(f"{caption}<pre>{escape(block.text)}</pre>")
            case Image():
                data = base64.b64encode(block.png).decode("ascii")
                caption = f'<p class="caption">{escape(block.caption)}</p>' if block.caption else ""
                parts.append(
                    f'<figure><img src="data:image/png;base64,{data}" '
                    f'style="width:{block.width_cm}cm">{caption}</figure>'
                )
            case PageBreak():
                parts.append('<div class="break"></div>')
    title = escape(doc.title)
    return (
        f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{title}</title>'
        f"<style>{css}</style></head><body>{''.join(parts)}</body></html>"
    )


def build_pdf(doc: Document) -> bytes:
    pdf = HTML(string=to_html(doc)).write_pdf()
    if not isinstance(pdf, bytes):
        raise RuntimeError("PDF 를 만들지 못했습니다")
    return pdf
