"""Generate native DOCX and PDF files from an AI Markdown report."""

from __future__ import annotations

import html
import re
from io import BytesIO

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


REPORT_TITLE = "C2Sherlock AI分析报告"
ACCENT = "064E3B"


def _clean_inline(text: str) -> str:
    text = re.sub(r"!\[[^\]]*]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)]\([^)]*\)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text.replace("**", "").replace("__", "").strip()


def _inline_pdf(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"__(.+?)__", r"<b>\1</b>", escaped)
    # The enclosing ParagraphStyle already uses STSong-Light. ReportLab cannot
    # resolve that CID font through an inline <font> tag.
    return re.sub(r"`(.+?)`", r"\1", escaped)


def parse_markdown(markdown: str) -> list[tuple[str, object]]:
    blocks: list[tuple[str, object]] = []
    paragraph: list[str] = []
    lines = markdown.replace("\r\n", "\n").split("\n")

    def flush_paragraph() -> None:
        if paragraph:
            content = " ".join(item.strip() for item in paragraph).strip()
            if content:
                blocks.append(("paragraph", content))
            paragraph.clear()

    index = 0
    while index < len(lines):
        raw = lines[index].strip()
        if not raw:
            flush_paragraph()
            index += 1
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", raw)
        if heading:
            flush_paragraph()
            blocks.append((f"h{min(len(heading.group(1)), 3)}", heading.group(2).strip()))
            index += 1
            continue
        bullet = re.match(r"^[-*+]\s+(.+)$", raw)
        numbered = re.match(r"^\d+[.)]\s+(.+)$", raw)
        if bullet or numbered:
            flush_paragraph()
            kind = "bullet" if bullet else "numbered"
            matcher = r"^[-*+]\s+(.+)$" if kind == "bullet" else r"^\d+[.)]\s+(.+)$"
            items: list[str] = []
            while index < len(lines):
                match = re.match(matcher, lines[index].strip())
                if not match:
                    break
                items.append(match.group(1).strip())
                index += 1
            blocks.append((kind, items))
            continue
        if raw.startswith("|") and raw.endswith("|"):
            flush_paragraph()
            rows: list[list[str]] = []
            while index < len(lines):
                candidate = lines[index].strip()
                if not (candidate.startswith("|") and candidate.endswith("|")):
                    break
                cells = [cell.strip() for cell in candidate.strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                    rows.append(cells)
                index += 1
            if rows:
                blocks.append(("table", rows))
            continue
        paragraph.append(raw)
        index += 1
    flush_paragraph()
    return blocks


def _set_run_font(run, size: float, *, bold: bool = False, color: str = "172033") -> None:
    run.font.name = "Microsoft YaHei"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor.from_string(color)


def build_docx(markdown: str) -> bytes:
    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.72)
    section.right_margin = Inches(0.72)
    title = document.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_after = Pt(18)
    _set_run_font(title.add_run(REPORT_TITLE), 20, bold=True, color=ACCENT)
    for kind, value in parse_markdown(markdown):
        if kind.startswith("h"):
            level = int(kind[1])
            paragraph = document.add_paragraph()
            paragraph.paragraph_format.space_before = Pt(12 if level == 1 else 8)
            paragraph.paragraph_format.space_after = Pt(6)
            _set_run_font(paragraph.add_run(_clean_inline(str(value))), 15 if level == 1 else 12.5, bold=True, color=ACCENT)
        elif kind == "paragraph":
            paragraph = document.add_paragraph()
            paragraph.paragraph_format.space_after = Pt(8)
            paragraph.paragraph_format.line_spacing = 1.45
            _set_run_font(paragraph.add_run(_clean_inline(str(value))), 10.5)
        elif kind in {"bullet", "numbered"}:
            style = "List Bullet" if kind == "bullet" else "List Number"
            for item in value:  # type: ignore[union-attr]
                paragraph = document.add_paragraph(style=style)
                paragraph.paragraph_format.space_after = Pt(4)
                _set_run_font(paragraph.add_run(_clean_inline(str(item))), 10.5)
        elif kind == "table":
            rows = value  # type: ignore[assignment]
            columns = max(len(row) for row in rows)
            table = document.add_table(rows=0, cols=columns)
            table.style = "Table Grid"
            for row_index, row in enumerate(rows):
                cells = table.add_row().cells
                for column_index in range(columns):
                    cell = cells[column_index]
                    cell.text = ""
                    text = row[column_index] if column_index < len(row) else ""
                    _set_run_font(cell.paragraphs[0].add_run(_clean_inline(text)), 9.5, bold=row_index == 0)
            document.add_paragraph().paragraph_format.space_after = Pt(3)
    output = BytesIO()
    document.save(output)
    return output.getvalue()


def build_pdf(markdown: str) -> bytes:
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm, title=REPORT_TITLE, author="C2Sherlock")
    base = getSampleStyleSheet()
    body = ParagraphStyle("ReportBody", parent=base["BodyText"], fontName="STSong-Light", fontSize=10.5, leading=17, spaceAfter=8, textColor=colors.HexColor("#172033"))
    title_style = ParagraphStyle("ReportTitle", parent=base["Title"], fontName="STSong-Light", fontSize=20, leading=28, alignment=TA_CENTER, spaceAfter=18, textColor=colors.HexColor(f"#{ACCENT}"))
    heading_styles = {
        "h1": ParagraphStyle("ReportH1", parent=base["Heading1"], fontName="STSong-Light", fontSize=15, leading=22, spaceBefore=12, spaceAfter=6, textColor=colors.HexColor(f"#{ACCENT}")),
        "h2": ParagraphStyle("ReportH2", parent=base["Heading2"], fontName="STSong-Light", fontSize=12.5, leading=19, spaceBefore=9, spaceAfter=5, textColor=colors.HexColor(f"#{ACCENT}")),
        "h3": ParagraphStyle("ReportH3", parent=base["Heading3"], fontName="STSong-Light", fontSize=11.5, leading=17, spaceBefore=7, spaceAfter=4, textColor=colors.HexColor(f"#{ACCENT}")),
    }
    story = [Paragraph(REPORT_TITLE, title_style)]
    for kind, value in parse_markdown(markdown):
        if kind.startswith("h"):
            story.append(Paragraph(_inline_pdf(str(value)), heading_styles[kind]))
        elif kind == "paragraph":
            story.append(Paragraph(_inline_pdf(str(value)), body))
        elif kind in {"bullet", "numbered"}:
            items = [ListItem(Paragraph(_inline_pdf(str(item)), body)) for item in value]  # type: ignore[union-attr]
            story.append(ListFlowable(items, bulletType="bullet" if kind == "bullet" else "1", leftIndent=16))
            story.append(Spacer(1, 4))
        elif kind == "table":
            rows = value  # type: ignore[assignment]
            data = [[Paragraph(_inline_pdf(cell), body) for cell in row] for row in rows]
            column_width = (A4[0] - 32 * mm) / max(len(row) for row in rows)
            table = Table(data, colWidths=[column_width] * max(len(row) for row in rows), repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), "STSong-Light"), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ECFDF5")), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D9D1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
            story.extend([table, Spacer(1, 8)])
    doc.build(story)
    return output.getvalue()
