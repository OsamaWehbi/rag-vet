"""PDF extraction with pypdf, tracking text a reader would not see.

Each piece of text from the content stream is classified using the graphics state pypdf passes
to its visitors:

- text render mode 3 (invisible text, also used for OCR layers; see below)
- white fill colour (assumes a white page; text drawn over a dark image is a false positive)
- an effective font size under 1.5 pt
- a position outside the page's MediaBox

Annotation text (/Contents) and document metadata are reported as hidden segments too.
Scanned PDFs often carry an invisible OCR layer drawn with render mode 3 under the page image.
That text is legitimate, so a page whose invisible text is most of the page is labelled as a
probable OCR layer, which the hidden-text rule treats as low severity unless it holds instructions.
"""

from __future__ import annotations

import math
from typing import Any

from rag_vet.models import Segment

TINY_PT = 1.5
OFF_PAGE_MARGIN = 5.0


def _mult(m: list[float], n: list[float]) -> list[float]:
    return [
        m[0] * n[0] + m[1] * n[2],
        m[0] * n[1] + m[1] * n[3],
        m[2] * n[0] + m[3] * n[2],
        m[2] * n[1] + m[3] * n[3],
        m[4] * n[0] + m[5] * n[2] + n[4],
        m[4] * n[1] + m[5] * n[3] + n[5],
    ]


def _is_white(operator: bytes, operands: list[Any]) -> bool | None:
    """True or False for fill-colour operators, None for anything else."""
    try:
        values = [float(v) for v in operands if isinstance(v, int | float) or hasattr(v, "as_numeric")]
    except (TypeError, ValueError):
        return None
    if operator in (b"rg", b"g"):
        return bool(values) and all(v >= 0.98 for v in values)
    if operator == b"k":
        return len(values) == 4 and all(v <= 0.02 for v in values)
    if operator in (b"sc", b"scn"):
        if len(values) in (1, 3):
            return all(v >= 0.98 for v in values)
        if len(values) == 4:
            return all(v <= 0.02 for v in values)
        return False
    return None


class _PageVisitor:
    def __init__(self, page_no: int, box: tuple[float, float, float, float]) -> None:
        self.page_no = page_no
        self.box = box
        self.render_mode = 0
        self.white = False
        self.saved: list[tuple[int, bool]] = []
        self.pieces: list[tuple[str, str | None]] = []

    def before(self, operator: bytes, operands: list[Any], cm: list[float], tm: list[float]) -> None:
        if operator == b"Tr" and operands:
            try:
                self.render_mode = int(operands[0])
            except (TypeError, ValueError):
                self.render_mode = 0
        elif operator == b"q":
            self.saved.append((self.render_mode, self.white))
        elif operator == b"Q":
            self.render_mode, self.white = self.saved.pop() if self.saved else (0, False)
        else:
            white = _is_white(operator, operands)
            if white is not None:
                self.white = white

    def text(self, text: str, cm: list[float], tm: list[float], font: Any, font_size: float) -> None:
        if not text:
            return
        reason: str | None = None
        m = _mult(list(tm), list(cm))
        size = abs(font_size) * math.hypot(m[2], m[3]) if font_size else 0.0
        x, y = m[4], m[5]
        x0, y0, x1, y1 = self.box
        if text.strip():
            if self.render_mode in (3, 7):
                reason = "invisible text (render mode 3)"
            elif self.white:
                reason = "white text"
            elif 0 < size < TINY_PT:
                reason = f"tiny font ({size:.2f} pt)"
            elif not (
                x0 - OFF_PAGE_MARGIN <= x <= x1 + OFF_PAGE_MARGIN and y0 - OFF_PAGE_MARGIN <= y <= y1 + OFF_PAGE_MARGIN
            ):
                reason = "outside the page"
        self.pieces.append((text, reason))

    def segments(self) -> list[Segment]:
        out: list[Segment] = []
        location = f"page {self.page_no}"
        invisible = sum(len(t.strip()) for t, r in self.pieces if r and r.startswith("invisible"))
        total = sum(len(t.strip()) for t, _ in self.pieces) or 1
        ocr_layer = invisible / total > 0.8
        for text, reason in self.pieces:
            if reason and reason.startswith("invisible") and ocr_layer:
                reason = "invisible text layer (probably OCR)"
            hidden = reason is not None
            if out and out[-1].hidden == hidden and out[-1].reason == (reason or ""):
                out[-1].text += text
            else:
                out.append(Segment(text, location, None, hidden=hidden, reason=reason or ""))
        return out


def _resolve(ref: Any) -> Any:
    """Resolve an indirect object, or None when it is broken; one bad annotation must not stop the scan."""
    try:
        return ref.get_object()
    except Exception:  # noqa: BLE001
        return None


def extract_pdf(path: str) -> list[Segment]:
    from pypdf import PdfReader

    reader = PdfReader(path)
    if reader.is_encrypted and not reader.decrypt(""):
        raise ValueError("encrypted PDF")
    segments: list[Segment] = []

    meta = reader.metadata or {}
    for key, value in meta.items():
        if isinstance(value, str) and value.strip() and key not in ("/Producer", "/CreationDate", "/ModDate"):
            segments.append(Segment(value, key.lstrip("/"), None, hidden=True, reason="PDF metadata"))

    for page_no, page in enumerate(reader.pages, start=1):
        box = page.mediabox
        visitor = _PageVisitor(page_no, (float(box.left), float(box.bottom), float(box.right), float(box.top)))
        page.extract_text(visitor_operand_before=visitor.before, visitor_text=visitor.text)
        segments.extend(visitor.segments())
        for annot in page.get("/Annots") or []:
            obj = _resolve(annot)
            if obj is None:
                continue
            contents = obj.get("/Contents")
            if isinstance(contents, str) and contents.strip():
                subtype = str(obj.get("/Subtype", "")).lstrip("/")
                segments.append(
                    Segment(contents, f"page {page_no}", None, hidden=True, reason=f"annotation ({subtype or 'note'})")
                )
    return segments
