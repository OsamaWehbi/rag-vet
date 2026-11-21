"""Find documents, extract them, run every rule and map findings back to lines and chunks."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from rag_vet import lockfile
from rag_vet.extract import SUPPORTED, load
from rag_vet.models import Document, Finding, Segment, Severity, printable
from rag_vet.rules import RULES
from rag_vet.rules import text as T

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
MIN_HIDDEN = 20
MIN_HIDDEN_WEAK = 200  # comments, metadata and alt text are often harmless; only long ones are reported
MAX_SCAN_CHARS = 5_000_000
WEAK_HIDDEN = (
    "HTML comment",
    "meta tag",
    "alt text",
    "image alt text",
    "title attribute",
    "aria-label attribute",
    "link title",
    "link reference definition",
    "PDF metadata",
    "document properties",
    "review comment",
    "annotation",
    "invisible text layer (probably OCR)",
    "clipped to nothing (visually hidden)",
)


@dataclass
class Options:
    chunk_size: int = 1000
    chunk_overlap: int = 200
    ignore: list[str] = field(default_factory=list)
    max_bytes: int = 50 * 1024 * 1024
    extensions: set[str] = field(default_factory=lambda: set(SUPPORTED))
    exclude: list[str] = field(default_factory=list)


@dataclass
class Result:
    findings: list[Finding]
    documents: list[Document]
    skipped: list[str]


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def discover(paths: list[Path], options: Options) -> tuple[list[tuple[Path, str]], list[str]]:
    """Files to scan, plus paths skipped because they are too large. Symlinks are not followed."""
    found: dict[str, Path] = {}
    skipped: list[str] = []

    def consider(p: Path, explicit: bool) -> None:
        shown = display_path(p)
        if any(fnmatch.fnmatch(shown, pat) for pat in options.exclude):
            return
        if not explicit and p.suffix.lower() not in options.extensions:
            return
        if p.is_symlink() and not explicit:
            return
        try:
            size = p.stat().st_size
        except OSError:
            return
        if size > options.max_bytes:
            skipped.append(shown)
            return
        found[shown] = p

    for root in paths:
        if root.is_file():
            consider(root, explicit=True)
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
            for name in sorted(filenames):
                consider(Path(dirpath) / name, explicit=False)
    return [(p, s) for s, p in sorted(found.items())], skipped


def _chunks(length: int, size: int, overlap: int) -> list[tuple[int, int]]:
    if size <= 0 or length == 0:
        return []
    step = max(1, size - max(0, min(overlap, size - 1)))
    out = []
    start = 0
    while True:
        out.append((start, min(start + size, length)))
        if start + size >= length:
            return out
        start += step


def _chunk_ids(span: tuple[int, int], chunks: list[tuple[int, int]]) -> tuple[list[int], bool]:
    """Chunks that fully contain the span, or, when none does, the chunks it is split across."""
    s, e = span
    whole = [i for i, (cs, ce) in enumerate(chunks) if cs <= s and e <= ce]
    if whole:
        return whole, False
    return [i for i, (cs, ce) in enumerate(chunks) if cs < e and s < ce], True


class _Builder:
    def __init__(self, doc: Document, options: Options) -> None:
        self.doc = doc
        self.options = options
        self.findings: list[Finding] = []
        self.offsets: list[int] = []
        pos = 0
        for seg in doc.segments:
            self.offsets.append(pos)
            pos += len(seg.text) + 1
        self.chunks = _chunks(max(0, pos - 1), options.chunk_size, options.chunk_overlap)

    def add(
        self,
        rule_id: str,
        evidence: str,
        segment: int | None = None,
        start: int = 0,
        end: int = 0,
        severity: Severity | None = None,
        location: str | None = None,
    ) -> None:
        rule = RULES[rule_id]
        line: int | None = None
        chunks: list[int] | None = None
        if segment is not None:
            seg: Segment = self.doc.segments[segment]
            location = location or seg.location or None
            if seg.line is not None:
                line = seg.line + seg.text.count("\n", 0, start)
                location = f"line {line}"
            if self.chunks and end > start:
                base = self.offsets[segment]
                ids, split = _chunk_ids((base + start, base + end), self.chunks)
                chunks = ids if ids and len(self.chunks) > 1 else None
                if split and len(ids) > 1:
                    evidence += " (split across chunks, so each chunk holds only part of it)"
        self.findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=severity or rule.severity,
                path=printable(self.doc.path) or "",
                location=printable(location),
                line=line,
                chunks=chunks,
                evidence=printable(evidence) or "",
                owasp=rule.owasp,
                remediation=rule.remediation,
            )
        )


def scan_document(doc: Document, options: Options) -> list[Finding]:
    b = _Builder(doc, options)
    if doc.error:
        b.add("RV501", doc.error)
        return b.findings

    budget = MAX_SCAN_CHARS
    grouped: dict[str, tuple[int, int]] = {}
    seen_urls: set[str] = set()
    for i, seg in enumerate(doc.segments):
        text = seg.text[:budget]
        budget -= len(text)
        if not text.strip():
            continue
        where = f" (in hidden text: {seg.reason})" if seg.hidden else ""

        injected = T.injections(text)
        if seg.hidden and injected:
            # One finding for hidden instructions: the concealment is what makes them dangerous.
            hit = injected[0]
            labels = hit.evidence.split("]", 1)[0].lstrip("[")
            b.add(
                "RV101",
                f"[{seg.reason}] contains instructions ({labels}): {T.snippet(text, hit.start, hit.end)}",
                i,
                hit.start,
                hit.end,
                Severity.HIGH,
            )
        else:
            for hit in injected:
                b.add(hit.rule_id, hit.evidence, i, hit.start, hit.end, hit.severity)

        detectors = (T.hidden_unicode, T.encoded_instructions, T.exfil_urls, T.secrets, T.personal_data)
        for detect in detectors:
            for hit in detect(text):
                if hit.rule_id == "RV201":
                    seen_urls.add(hit.evidence.split("] ", 1)[1])
                b.add(hit.rule_id, hit.evidence + where, i, hit.start, hit.end, hit.severity)

        if seg.hidden and not injected:
            size = len(text.strip())
            weak = seg.reason.startswith(WEAK_HIDDEN)
            if size >= (MIN_HIDDEN_WEAK if weak else MIN_HIDDEN):
                count, first = grouped.get(seg.reason, (0, i))
                grouped[seg.reason] = (count + 1, first)
        if budget <= 0:
            break

    for reason, (count, first) in grouped.items():
        seg = doc.segments[first]
        weak = reason.startswith(WEAK_HIDDEN)
        more = f" (+{count - 1} more)" if count > 1 else ""
        b.add(
            "RV101",
            f"[{reason}] {T.snippet(seg.text, 0, min(len(seg.text), 80), 0)}{more}",
            first,
            0,
            len(seg.text),
            Severity.LOW if weak else None,
        )

    links = [(link.url, link.image) for link in doc.links if link.url not in seen_urls]
    for hit in T.exfil_urls("", links):
        if hit.evidence.split("] ", 1)[1] not in seen_urls:
            b.add(hit.rule_id, hit.evidence, None, severity=hit.severity, location="links")
    return b.findings


def _ignored(f: Finding, patterns: list[str]) -> bool:
    for pattern in patterns:
        rule, _, glob = pattern.partition(":")
        if rule.upper() == f.rule_id and (not glob or fnmatch.fnmatch(f.path, glob)):
            return True
    return False


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.path, f.location or "")
        if f.rule_id in ("RV101", "RV201", "RV302"):
            key = (*key[:2], (f.location or "") + "|" + f.evidence)
        old = best.get(key)
        if old is None or f.severity.rank > old.severity.rank:
            best[key] = f
    return sorted(best.values(), key=Finding.sort_key)


def check_lock(lock: dict[str, str], current: dict[str, Path]) -> list[Finding]:
    out: list[Finding] = []
    for shown, path in current.items():
        pinned = lock.get(shown)
        if pinned is None:
            rule = RULES["RV402"]
            out.append(_lock_finding(rule.id, shown, "not in lockfile"))
        elif pinned != lockfile.digest(path):
            out.append(_lock_finding("RV401", shown, f"pinned {pinned[:19]}..."))
    for shown in lock:
        if shown not in current:
            out.append(_lock_finding("RV403", shown, "in lockfile but not found"))
    return out


def _lock_finding(rule_id: str, path: str, evidence: str) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        path=printable(path) or "",
        evidence=evidence,
        owasp=rule.owasp,
        remediation=rule.remediation,
    )


def scan(paths: list[Path], options: Options, lock: dict[str, str] | None = None) -> Result:
    files, skipped = discover(paths, options)
    documents: list[Document] = []
    findings: list[Finding] = []
    for path, shown in files:
        doc = load(path, shown)
        documents.append(doc)
        findings.extend(scan_document(doc, options))
    if lock is not None:
        findings.extend(check_lock(lock, {shown: path for path, shown in files}))
    findings = [f for f in _dedupe(findings) if not _ignored(f, options.ignore)]
    return Result(findings, documents, skipped)


def summarise(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
