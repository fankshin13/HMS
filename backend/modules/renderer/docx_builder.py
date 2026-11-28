"""중립 문서 → DOCX (python-docx).

표 레이아웃 불변식: 모든 행에 w:cantSplit(행이 페이지 경계에서 쪼개지지 않음),
머리글 행에 w:tblHeader(페이지마다 반복)와 keep_with_next(머리글이 첫 행과 떨어지지 않음).
"""

import io

from docx import Document as new_document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.oxml.xmlchemy import BaseOxmlElement
from docx.shared import Cm, Pt, RGBColor
from docx.table import Table as DocxTable
from docx.table import _Cell, _Row
from docx.text.paragraph import Paragraph as DocxParagraph
from docx.text.run import Run

from modules.renderer.fonts import DOCX_EAST_ASIA
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
    Tone,
)

TONE_COLORS: dict[Tone, RGBColor | None] = {
    "danger": RGBColor(0xB4, 0x23, 0x18),
    "warning": RGBColor(0xB5, 0x47, 0x08),
    "safe": RGBColor(0x1E, 0x7F, 0x4F),
    "muted": RGBColor(0x66, 0x70, 0x85),
    "plain": None,
}
HEADER_FILL = "EEF1F5"
CODE_FILL = "F4F5F7"
BORDER = "C9CED6"
MONO = "Consolas"
CONTENT_WIDTH_CM = 17.0


def _font(run: Run, name: str = DOCX_EAST_ASIA, size: float | None = None) -> None:
    run.font.name = name
    r_pr = run._r.get_or_add_rPr()
    fonts = r_pr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        r_pr.insert(0, fonts)
    fonts.set(qn("w:eastAsia"), DOCX_EAST_ASIA)
    if size is not None:
        run.font.size = Pt(size)


def _shade(element: BaseOxmlElement, fill: str) -> None:
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    element.append(shd)


def _keep_with_next(paragraph: DocxParagraph) -> None:
    paragraph.paragraph_format.keep_with_next = True


def _row_props(row: _Row, *, header: bool) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:cantSplit"))
    if header:
        tr_pr.append(OxmlElement("w:tblHeader"))


def _borders(table: DocxTable) -> None:
    tbl_pr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        element = OxmlElement(f"w:{edge}")
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), "4")
        element.set(qn("w:color"), BORDER)
        borders.append(element)
    tbl_pr.append(borders)


def _write_cell(cell_obj: _Cell, value: Cell, *, size: float, header: bool) -> None:
    paragraph = cell_obj.paragraphs[0]
    paragraph.paragraph_format.space_after = Pt(0)
    lines = value.text.split("\n")
    for index, line in enumerate(lines):
        run = paragraph.add_run(line)
        _font(run, size=size)
        run.bold = value.bold or header
        color = TONE_COLORS[value.tone]
        if color is not None:
            run.font.color.rgb = color
        if index < len(lines) - 1:
            run.add_break()
    if header:
        _keep_with_next(paragraph)
        _shade(cell_obj._tc.get_or_add_tcPr(), HEADER_FILL)


class _Builder:
    def __init__(self, doc: Document) -> None:
        self.source = doc
        self.doc = new_document()
        section = self.doc.sections[0]
        section.orientation = WD_ORIENT.PORTRAIT
        section.page_width, section.page_height = Cm(21.0), Cm(29.7)
        section.left_margin = section.right_margin = Cm(2.0)
        section.top_margin = section.bottom_margin = Cm(2.0)
        normal = self.doc.styles["Normal"]
        normal.font.name = DOCX_EAST_ASIA
        normal.font.size = Pt(10)
        r_pr = normal.element.get_or_add_rPr()
        fonts = r_pr.find(qn("w:rFonts"))
        if fonts is None:
            fonts = OxmlElement("w:rFonts")
            r_pr.insert(0, fonts)
        fonts.set(qn("w:eastAsia"), DOCX_EAST_ASIA)
        self._header_footer(doc.header)
        self.doc.core_properties.title = doc.title

    def _header_footer(self, text: str) -> None:
        section = self.doc.sections[0]
        head = section.header.paragraphs[0]
        head.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        run = head.add_run(text)
        _font(run, size=8)
        run.font.color.rgb = TONE_COLORS["muted"]
        foot = section.footer.paragraphs[0]
        foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
        self._page_field(foot)

    def _page_field(self, paragraph: DocxParagraph) -> None:
        run = paragraph.add_run()
        _font(run, size=8)
        for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
            if kind:
                element = OxmlElement("w:fldChar")
                element.set(qn("w:fldCharType"), kind)
            else:
                element = OxmlElement("w:instrText")
                element.set(qn("xml:space"), "preserve")
                element.text = text
            run._r.append(element)

    def build(self) -> bytes:
        for block in self.source.blocks:
            match block:
                case Cover():
                    self.cover(block)
                case Heading():
                    self.heading(block)
                case Paragraph():
                    self.paragraph(block)
                case Table():
                    self.table(block)
                case KeyValues():
                    self.key_values(block)
                case Code():
                    self.code(block)
                case Image():
                    self.image(block)
                case PageBreak():
                    self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
        buffer = io.BytesIO()
        self.doc.save(buffer)
        return buffer.getvalue()

    def cover(self, block: Cover) -> None:
        for _ in range(6):
            self.doc.add_paragraph()
        title = self.doc.add_paragraph()
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = title.add_run(block.title)
        _font(run, size=24)
        run.bold = True
        subtitle = self.doc.add_paragraph()
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        sub = subtitle.add_run(block.subtitle)
        _font(sub, size=12)
        sub.font.color.rgb = TONE_COLORS["muted"]
        for _ in range(4):
            self.doc.add_paragraph()
        self.key_values(KeyValues(block.meta))

    def heading(self, block: Heading) -> None:
        paragraph = self.doc.add_paragraph()
        paragraph.paragraph_format.space_before = Pt({1: 14, 2: 10, 3: 8}[block.level])
        paragraph.paragraph_format.space_after = Pt(4)
        _keep_with_next(paragraph)
        run = paragraph.add_run(block.text)
        _font(run, size={1: 15, 2: 12.5, 3: 10.5}[block.level])
        run.bold = True

    def paragraph(self, block: Paragraph) -> None:
        paragraph = self.doc.add_paragraph()
        paragraph.paragraph_format.space_after = Pt(4)
        run = paragraph.add_run(block.text)
        _font(run, size=8.5 if block.small else 10)
        color = TONE_COLORS["muted" if block.small and block.tone == "plain" else block.tone]
        if color is not None:
            run.font.color.rgb = color

    def table(self, block: Table) -> None:
        table = self.doc.add_table(rows=1, cols=len(block.headers))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        _borders(table)
        widths = block.widths or [1] * len(block.headers)
        total = sum(widths)
        size = 8.0 if len(block.headers) > 5 else 9.0
        header = table.rows[0]
        _row_props(header, header=True)
        for index, text in enumerate(block.headers):
            _write_cell(header.cells[index], Cell(text), size=size, header=True)
        for values in block.rows:
            row = table.add_row()
            _row_props(row, header=False)
            for index, value in enumerate(values[: len(block.headers)]):
                _write_cell(row.cells[index], value, size=size, header=False)
        for index, width in enumerate(widths):
            column_width = Cm(CONTENT_WIDTH_CM * width / total)
            for row in table.rows:
                row.cells[index].width = column_width
        if block.caption:
            self.paragraph(Paragraph(block.caption, small=True))
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def key_values(self, block: KeyValues) -> None:
        table = self.doc.add_table(rows=0, cols=2)
        table.autofit = False
        _borders(table)
        for key, value in block.pairs:
            row = table.add_row()
            _row_props(row, header=False)
            _write_cell(row.cells[0], Cell(key, bold=True), size=9, header=False)
            _shade(row.cells[0]._tc.get_or_add_tcPr(), HEADER_FILL)
            _write_cell(row.cells[1], Cell(value), size=9, header=False)
            row.cells[0].width = Cm(3.6)
            row.cells[1].width = Cm(CONTENT_WIDTH_CM - 3.6)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def code(self, block: Code) -> None:
        if block.caption:
            caption = self.doc.add_paragraph()
            caption.paragraph_format.space_after = Pt(1)
            _keep_with_next(caption)
            run = caption.add_run(block.caption)
            _font(run, size=8)
            run.font.color.rgb = TONE_COLORS["muted"]
        paragraph = self.doc.add_paragraph()
        paragraph.paragraph_format.space_after = Pt(6)
        _shade(paragraph._p.get_or_add_pPr(), CODE_FILL)
        lines = block.text.split("\n")
        for index, line in enumerate(lines):
            run = paragraph.add_run(line)
            _font(run, name=MONO, size=7.5)
            if index < len(lines) - 1:
                run.add_break()

    def image(self, block: Image) -> None:
        paragraph = self.doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        paragraph.add_run().add_picture(io.BytesIO(block.png), width=Cm(block.width_cm))
        if block.caption:
            caption = self.doc.add_paragraph()
            caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = caption.add_run(block.caption)
            _font(run, size=8)
            run.font.color.rgb = TONE_COLORS["muted"]


def build_docx(doc: Document) -> bytes:
    return _Builder(doc).build()
