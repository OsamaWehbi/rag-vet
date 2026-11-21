"""Turn files into Documents: the text a RAG loader would index, split into visible and hidden segments."""

from __future__ import annotations

from pathlib import Path

from rag_vet.models import Document, Segment

MARKDOWN = {".md", ".markdown", ".mdx"}
HTML = {".html", ".htm", ".xhtml"}
TEXT = {".txt", ".rst", ".csv", ".tsv", ".json", ".jsonl", ".yaml", ".yml", ".xml", ".log", ".tex"}
SUPPORTED = MARKDOWN | HTML | TEXT | {".pdf", ".docx"}


def kind_of(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in MARKDOWN:
        return "markdown"
    if ext in HTML:
        return "html"
    if ext in TEXT:
        return "text"
    if ext == ".pdf":
        return "pdf"
    if ext == ".docx":
        return "docx"
    return None


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8-sig",):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def load(path: Path, display: str) -> Document:
    """Extract a document. Parse failures are recorded on the Document instead of raised."""
    kind = kind_of(path) or "text"
    doc = Document(path=display, kind=kind)
    try:
        if kind == "pdf":
            from rag_vet.extract.pdf import extract_pdf

            doc.segments = extract_pdf(str(path))
        elif kind == "docx":
            from rag_vet.extract.docx import extract_docx

            doc.segments, doc.links = extract_docx(str(path))
        elif kind == "html":
            from rag_vet.extract.html import extract_html

            doc.segments, doc.links = extract_html(_read_text(path))
        elif kind == "markdown":
            from rag_vet.extract.markdown import extract_markdown

            doc.segments, doc.links = extract_markdown(_read_text(path))
        else:
            doc.segments = [Segment(_read_text(path), "line 1", 1)]
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop a corpus scan
        doc.error = f"{type(exc).__name__}: {exc}"[:300]
    return doc
