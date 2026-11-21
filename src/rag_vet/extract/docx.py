"""DOCX extraction with python-docx, tracking hidden runs.

Every paragraph in the body is visited, including paragraphs inside tables and text boxes, plus
headers and footers. A run is hidden when Word would not show it: the "hidden" font property
(w:vanish, set on the run or its styles), white text without shading, or a font under 2 pt.
Core document properties (title, subject, keywords, comments) are reported as hidden segments.
"""

from __future__ import annotations

import contextlib
from typing import Any

from rag_vet.models import Link, Segment

TINY_PT = 2.0
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _style_chain_hidden(style: Any) -> bool:
    depth = 0
    while style is not None and depth < 20:
        if style.font is not None and style.font.hidden:
            return True
        style = style.base_style
        depth += 1
    return False


def _run_reason(run: Any, paragraph_style_hidden: bool) -> str | None:
    font = run.font
    if font.hidden or (font.hidden is None and (paragraph_style_hidden or _style_chain_hidden(run.style))):
        return "hidden text (Word hidden font)"
    rgb = font.color.rgb if font.color is not None and font.color.type is not None else None
    shaded = run._r.find(f"{_W}rPr/{_W}shd") is not None or run._r.find(f"{_W}rPr/{_W}highlight") is not None
    if rgb is not None and str(rgb).upper() in ("FFFFFF", "FEFEFE") and not shaded:
        return "white text"
    if font.size is not None and font.size.pt < TINY_PT:
        return f"tiny font ({font.size.pt:g} pt)"
    return None


def _paragraph_segments(paragraph: Any, location: str) -> list[Segment]:
    out: list[Segment] = []
    style_hidden = _style_chain_hidden(paragraph.style) if paragraph.style is not None else False
    for run in paragraph.runs:
        text = run.text
        if not text:
            continue
        reason = _run_reason(run, style_hidden)
        hidden = reason is not None
        if out and out[-1].hidden == hidden and out[-1].reason == (reason or ""):
            out[-1].text += text
        else:
            out.append(Segment(text, location, None, hidden=hidden, reason=reason or ""))
    if out:
        out[-1].text += "\n"
    return out


def _comments(document: Any) -> list[Segment]:
    """Review comments. Best effort: python-docx only reads them from version 1.2."""
    out: list[Segment] = []
    with contextlib.suppress(Exception):
        for comment in getattr(document, "comments", None) or []:
            text = comment.text
            if text and text.strip():
                out.append(Segment(text, "comments", None, hidden=True, reason="review comment"))
    return out


def extract_docx(path: str) -> tuple[list[Segment], list[Link]]:
    import docx
    from docx.text.paragraph import Paragraph

    document = docx.Document(path)
    segments: list[Segment] = []

    props = document.core_properties
    for name in ("title", "subject", "keywords", "comments", "category", "author", "last_modified_by"):
        value = getattr(props, name, None)
        if isinstance(value, str) and value.strip():
            segments.append(Segment(value, f"properties {name}", None, hidden=True, reason="document properties"))

    for n, p in enumerate(document.element.body.iter(f"{_W}p"), start=1):
        segments.extend(_paragraph_segments(Paragraph(p, document), f"paragraph {n}"))

    for s, section in enumerate(document.sections, start=1):
        for part_name in ("header", "footer"):
            part = getattr(section, part_name)
            if part is None or part.is_linked_to_previous:
                continue
            for p in part.paragraphs:
                segments.extend(_paragraph_segments(p, f"section {s} {part_name}"))

    segments.extend(_comments(document))

    links = [
        Link(rel.target_ref, "hyperlink", None)
        for rel in document.part.rels.values()
        if rel.reltype.endswith("/hyperlink") and rel.is_external
    ]
    return segments, links
