"""Command-line interface: scan, extract, pin and rules."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from rag_vet import __version__, lockfile, report
from rag_vet.engine import Options, discover, scan
from rag_vet.extract import load
from rag_vet.models import Severity, printable
from rag_vet.rules import RULES

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Scan documents for hidden instructions, exfiltration links and secrets before they enter a RAG index.",
)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)


class Format(StrEnum):
    table = "table"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


class FailOn(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    none = "none"


def _version(value: bool) -> None:
    if value:
        console.print(f"rag-vet {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show the version."),
) -> None:
    pass


def _options(chunk_size: int, chunk_overlap: int, ignore: list[str], exclude: list[str], max_mb: int) -> Options:
    if chunk_overlap >= chunk_size > 0:
        raise typer.BadParameter("--chunk-overlap must be smaller than --chunk-size")
    return Options(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        ignore=ignore,
        exclude=exclude,
        max_bytes=max_mb * 1024 * 1024,
    )


@app.command("scan")
def scan_cmd(
    paths: list[Path] = typer.Argument(..., exists=True, help="Files or directories to scan."),
    fmt: Format = typer.Option(Format.table, "--format", "-f", help="Output format."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report to a file instead of stdout."),
    fail_on: FailOn = typer.Option(FailOn.high, help="Exit with status 1 when a finding is at or above this severity."),
    lock: Path | None = typer.Option(None, "--lock", help="Compare documents with this lockfile (see `rag-vet pin`)."),
    ignore: list[str] = typer.Option(
        [], "--ignore", help="Ignore a rule, optionally for matching paths: RV102 or RV102:docs/security/*."
    ),
    exclude: list[str] = typer.Option([], "--exclude", help="Skip paths matching this glob, for example 'archive/*'."),
    chunk_size: int = typer.Option(1000, help="Chunk size in characters used to report chunk numbers (0 disables)."),
    chunk_overlap: int = typer.Option(200, help="Chunk overlap in characters."),
    max_mb: int = typer.Option(50, "--max-file-size", help="Skip files larger than this many MB."),
    summary: Path | None = typer.Option(
        None, "--summary", help="Append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY)."
    ),
) -> None:
    """Scan documents and report findings."""
    options = _options(chunk_size, chunk_overlap, ignore, exclude, max_mb)
    pins = None
    if lock is not None and lock.exists():
        try:
            pins = lockfile.read(lock)
        except (ValueError, OSError) as exc:
            err.print(f"[red]error:[/] {escape(str(exc))}")
            raise typer.Exit(2) from exc
    elif lock is not None:
        err.print(f"[yellow]warning:[/] lockfile {escape(str(lock))} not found; run `rag-vet pin` to create it")

    result = scan(paths, options, pins)

    if fmt is Format.table and output is None:
        report.render_table(result, console)
    else:
        rendered = {
            Format.table: lambda: report.to_markdown(result),
            Format.json: lambda: report.to_json(result),
            Format.sarif: lambda: report.to_sarif(result),
            Format.markdown: lambda: report.to_markdown(result),
        }[fmt]()
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
            err.print(
                f"wrote {escape(str(output))}: {len(result.findings)} finding(s) in {escape(report.scope(result))}"
            )
        else:
            sys.stdout.write(rendered if rendered.endswith("\n") else rendered + "\n")
    if summary is not None:
        with summary.open("a", encoding="utf-8") as f:
            f.write(report.to_markdown(result))

    if fail_on is not FailOn.none:
        threshold = Severity(fail_on.value).rank
        if any(f.severity.rank >= threshold for f in result.findings):
            raise typer.Exit(1)


@app.command("extract")
def extract_cmd(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="The document to inspect."),
    hidden: bool = typer.Option(False, "--hidden", help="Show only hidden segments."),
) -> None:
    """Show the text a RAG loader would extract, marking what a reader would not see."""
    doc = load(path, path.as_posix())
    if doc.error:
        err.print(f"[red]error:[/] could not parse {escape(str(path))}: {escape(doc.error)}")
        raise typer.Exit(2)
    shown = 0
    for seg in doc.segments:
        if not seg.text.strip() or (hidden and not seg.hidden):
            continue
        shown += 1
        label = f"[bold red]HIDDEN[/] [red]{escape(seg.reason)}[/]" if seg.hidden else "[green]visible[/]"
        console.print(f"{label} [dim]{escape(seg.location)}[/]")
        console.print(escape(printable(seg.text.strip()) or ""), soft_wrap=True)
        console.print()
    if hidden and not shown:
        console.print("[green]No hidden text found.[/]")


@app.command("pin")
def pin_cmd(
    paths: list[Path] = typer.Argument(..., exists=True, help="Files or directories to pin."),
    lock: Path = typer.Option(Path("rag-vet.lock"), "--lock", help="Lockfile to write."),
    exclude: list[str] = typer.Option([], "--exclude", help="Skip paths matching this glob."),
) -> None:
    """Record a SHA-256 for every document, so later scans report what changed."""
    files, skipped = discover(paths, Options(exclude=exclude))
    lockfile.write(lock, {shown: lockfile.digest(path) for path, shown in files})
    console.print(f"pinned {len(files)} document(s) to {escape(str(lock))}")
    for s in skipped:
        err.print(f"[yellow]skipped (too large):[/] {escape(s)}")


@app.command("rules")
def rules_cmd() -> None:
    """List the rules."""
    table = Table(header_style="bold")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("OWASP")
    for rule in RULES.values():
        table.add_row(rule.id, str(rule.severity), rule.title, rule.owasp)
    console.print(table)


def main() -> None:
    # Never crash on a console that cannot show a character from a document.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    # Click expands wildcards in arguments on Windows, which would turn --exclude/--ignore globs into file paths.
    app(windows_expand_args=False)
