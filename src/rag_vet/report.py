"""Render findings as a terminal table, JSON, SARIF 2.1.0 or Markdown."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from rag_vet import __version__
from rag_vet.engine import Result, summarise
from rag_vet.models import Finding, Severity
from rag_vet.rules import RULES

SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "3.0", Severity.INFO: "1.0"}
STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}
HELP_URI = "https://github.com/OsamaWehbi/rag-vet/blob/main/docs/rules.md"


def target(f: Finding) -> str:
    if f.line is not None:
        return f"{f.path}:{f.line}"
    return f"{f.path} ({f.location})" if f.location else f.path


def scope(result: Result) -> str:
    kinds: dict[str, int] = {}
    for doc in result.documents:
        kinds[doc.kind] = kinds.get(doc.kind, 0) + 1
    detail = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
    text = f"{len(result.documents)} document(s)" + (f" ({detail})" if detail else "")
    if result.skipped:
        text += f", {len(result.skipped)} skipped as too large"
    return text


def _detail(f: Finding) -> str:
    chunks = f"chunk {', '.join(map(str, f.chunks))}" if f.chunks else ""
    return chunks


def render_table(result: Result, console: Console) -> None:
    console.print(f"[bold]rag-vet {__version__}[/] scanned {escape(scope(result))}")
    if not result.findings:
        console.print("[green]No findings.[/]")
        return
    table = Table(header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Location", overflow="fold")
    table.add_column("Finding", overflow="fold")
    for f in result.findings:
        detail = escape(f.title)
        if f.evidence:
            detail += f"\n[dim]{escape(f.evidence)}[/]"
        extra = _detail(f)
        if extra:
            detail += f"\n[dim]{escape(extra)}[/]"
        table.add_row(f"[{STYLE[f.severity]}]{f.severity}[/]", f.rule_id, escape(target(f)), detail)
    console.print(table)
    console.print("  ".join(f"{k}: {v}" for k, v in summarise(result.findings).items()))


def to_json(result: Result) -> str:
    doc = {
        "tool": "rag-vet",
        "version": __version__,
        "documents": [
            {"path": d.path, "kind": d.kind, "segments": len(d.segments), "hidden": len(d.hidden), "error": d.error}
            for d in result.documents
        ],
        "skipped": result.skipped,
        "summary": summarise(result.findings),
        "findings": [f.model_dump(mode="json") for f in result.findings],
    }
    return json.dumps(doc, indent=2)


def _fingerprint(f: Finding) -> str:
    evidence = hashlib.sha256(f.evidence.encode("utf-8")).hexdigest()[:16]
    return f"{f.rule_id}:{f.path}:{f.location or ''}:{evidence}"


def to_sarif(result: Result) -> str:
    """SARIF 2.1.0 for GitHub code scanning. Results point at the document and, when known, the line."""
    used = sorted({f.rule_id for f in result.findings})
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for i, rid in enumerate(used):
        rule = RULES[rid]
        index[rid] = i
        rules.append(
            {
                "id": rid,
                "name": rule.title.replace(" ", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation, "markdown": f"{rule.remediation}\n\nOWASP: {rule.owasp}"},
                "helpUri": f"{HELP_URI}#{rid.lower()}",
                "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": ["security", "rag", rule.owasp],
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = []
    for f in result.findings:
        message = f"{f.title}: {target(f)}. {f.evidence}".strip()
        region: dict[str, Any] = {"startLine": f.line or 1}
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": index[f.rule_id],
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": message},
                "partialFingerprints": {"ragVetFinding/v1": _fingerprint(f)},
                "properties": {"security-severity": SECURITY_SEVERITY[f.severity]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": region}}],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rag-vet",
                        "version": __version__,
                        "informationUri": "https://github.com/OsamaWehbi/rag-vet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'").replace("\n", " ")


def to_markdown(result: Result) -> str:
    lines = [f"### rag-vet: {scope(result)}", ""]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    counts = summarise(result.findings)
    lines += [", ".join(f"**{k}**: {v}" for k, v in counts.items()), ""]
    lines += ["| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |"]
    for f in result.findings:
        detail = _md(f.title) + (f"<br>`{_md(f.evidence)}`" if f.evidence else "")
        lines.append(f"| {f.severity} | {f.rule_id} | `{_md(target(f))}` | {detail} |")
    return "\n".join(lines) + "\n"
