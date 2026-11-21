"""Core data types: extracted documents, segments of text and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


def printable(text: str | None) -> str | None:
    """Escape control and invisible characters so hostile text cannot drive the terminal or hide in reports."""
    if text is None:
        return None
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in text)


@dataclass
class Segment:
    """A run of text pulled out of a document.

    `hidden` is set when a person reading the rendered document would not see the text but a
    text extractor (and so the RAG index) would. `reason` says why, for example "display:none".
    """

    text: str
    location: str = ""
    line: int | None = None
    hidden: bool = False
    reason: str = ""


@dataclass
class Link:
    url: str
    location: str = ""
    line: int | None = None
    image: bool = False


@dataclass
class Document:
    path: str
    kind: str
    segments: list[Segment] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    error: str | None = None

    @property
    def text(self) -> str:
        """Everything an extractor would hand to the chunker, in document order."""
        return "\n".join(s.text for s in self.segments if s.text)

    @property
    def hidden(self) -> list[Segment]:
        return [s for s in self.segments if s.hidden and s.text.strip()]


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    path: str
    location: str | None = None
    line: int | None = None
    chunks: list[int] | None = None
    evidence: str = ""
    owasp: str = ""
    remediation: str = ""

    def sort_key(self) -> tuple[int, str, str, int, str]:
        return (-self.severity.rank, self.path, self.rule_id, self.line or 0, self.evidence)
