"""Markdown extraction.

Markdown is passed through the HTML visibility parser, because raw HTML inside Markdown is how
most hidden text gets in (comments, `<span style="display:none">`, `<div hidden>`). Code is
escaped first, so an HTML example inside a code block is shown as code, not treated as markup.
Link reference definitions, link titles and image alt text are not shown as body text, so they
are reported as hidden segments too.
"""

from __future__ import annotations

import re

from rag_vet.extract.html import extract_html
from rag_vet.models import Link, Segment

_FENCE = re.compile(r"^(?P<fence>`{3,}|~{3,})[^\n]*\n.*?^(?P=fence)[ \t]*$", re.M | re.S)
_INLINE_CODE = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.S)
_LINK = re.compile(
    r"(?P<bang>!?)\[(?P<label>[^\]\n]*)\]\(\s*<?(?P<url>[^\s)>]+)>?(?:\s+[\"'(](?P<title>[^\"')]*)[\"')])?\s*\)"
)
_REF_DEF = re.compile(
    r"^[ ]{0,3}\[(?P<label>[^\]\n]+)\]:\s*<?(?P<url>\S+?)>?(?:\s+[\"'(](?P<title>[^\n]*)[\"')])?[ \t]*$", re.M
)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;")


def _escape_code(text: str) -> str:
    """Escape markup inside fenced blocks and inline code spans, each exactly once."""
    out: list[str] = []
    pos = 0
    for m in _FENCE.finditer(text):
        out.append(_INLINE_CODE.sub(lambda c: _escape(c.group(0)), text[pos : m.start()]))
        out.append(_escape(m.group(0)))
        pos = m.end()
    out.append(_INLINE_CODE.sub(lambda c: _escape(c.group(0)), text[pos:]))
    return "".join(out)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def extract_markdown(text: str) -> tuple[list[Segment], list[Link]]:
    extras: list[Segment] = []
    links: list[Link] = []

    for m in _REF_DEF.finditer(text):
        line = _line_at(text, m.start())
        links.append(Link(m.group("url"), f"line {line}", line))
        hidden = f"[{m.group('label')}]: {m.group('url')}" + (f" {m.group('title')}" if m.group("title") else "")
        extras.append(Segment(hidden, f"line {line}", line, hidden=True, reason="link reference definition"))

    body = _REF_DEF.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    for m in _LINK.finditer(body):
        line = _line_at(body, m.start())
        links.append(Link(m.group("url"), f"line {line}", line, image=bool(m.group("bang"))))
        if m.group("bang") and m.group("label").strip():
            extras.append(Segment(m.group("label"), f"line {line}", line, hidden=True, reason="image alt text"))
        if m.group("title"):
            extras.append(Segment(m.group("title"), f"line {line}", line, hidden=True, reason="link title"))

    segments, html_links = extract_html(_escape_code(body))
    return segments + extras, links + html_links
