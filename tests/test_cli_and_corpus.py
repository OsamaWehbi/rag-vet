import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import ROOT, rules
from rag_vet import __version__
from rag_vet.cli import app
from rag_vet.engine import Options, scan

CORPUS = ROOT / "examples" / "corpus"
runner = CliRunner()

EXPECTED = {
    "benefits.docx": {"RV101"},
    "hr-policy.md": {"RV101", "RV201"},
    "meeting-notes.txt": {"RV103", "RV104", "RV301", "RV302"},
    "product-page.html": {"RV101"},
    "vendor-agreement.pdf": {"RV101"},
}


def test_clean_corpus_has_no_findings():
    result = scan([CORPUS / "clean"], Options())
    assert result.findings == []
    assert len(result.documents) == 4


def test_poisoned_corpus_findings_per_file():
    result = scan([CORPUS / "poisoned"], Options())
    by_file: dict[str, set[str]] = {}
    for f in result.findings:
        by_file.setdefault(Path(f.path).name, set()).add(f.rule_id)
    assert by_file == EXPECTED
    hidden_techniques = {f.evidence.split("]")[0] for f in result.findings if f.rule_id == "RV101"}
    for technique in (
        "[white text",
        "[invisible text (render mode 3)",
        "[tiny font (0.50 pt)",
        "[outside the page",
        "[hidden text (Word hidden font)",
        "[display:none",
        "[font-size:0px",
        "[HTML comment",
        "[meta tag",
    ):
        assert technique in hidden_techniques


def test_cli_exit_codes_and_version():
    assert runner.invoke(app, ["--version"]).output.strip() == f"rag-vet {__version__}"
    assert runner.invoke(app, ["scan", str(CORPUS / "clean")]).exit_code == 0
    assert runner.invoke(app, ["scan", str(CORPUS / "poisoned")]).exit_code == 1
    assert runner.invoke(app, ["scan", str(CORPUS / "poisoned"), "--fail-on", "none"]).exit_code == 0


def test_cli_json_sarif_and_markdown(tmp_path):
    out = runner.invoke(app, ["scan", str(CORPUS / "poisoned"), "-f", "json", "--fail-on", "none"])
    doc = json.loads(out.output)
    assert doc["tool"] == "rag-vet"
    assert doc["summary"]["high"] >= 10

    sarif_path = tmp_path / "r.sarif"
    summary = tmp_path / "summary.md"
    result = runner.invoke(
        app,
        [
            "scan",
            str(CORPUS / "poisoned"),
            "-f",
            "sarif",
            "-o",
            str(sarif_path),
            "--summary",
            str(summary),
            "--fail-on",
            "none",
        ],
    )
    assert result.exit_code == 0
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert results
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in results)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {r["ruleId"] for r in results}
    assert summary.read_text(encoding="utf-8").startswith("### rag-vet:")


def test_cli_extract_hidden():
    out = runner.invoke(app, ["extract", "--hidden", str(CORPUS / "poisoned" / "vendor-agreement.pdf")])
    assert out.exit_code == 0
    assert "HIDDEN" in out.output
    assert "render mode 3" in out.output
    assert "Payment terms" not in out.output
    clean = runner.invoke(app, ["extract", "--hidden", str(CORPUS / "clean" / "faq.html")])
    assert "HIDDEN" in clean.output  # meta description and alt text are listed, even though scan ignores short ones


def test_pin_and_lock_changes(tmp_path, monkeypatch):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.md").write_text("first version", encoding="utf-8")
    (corpus / "b.md").write_text("stays", encoding="utf-8")
    (corpus / "c.md").write_text("will be removed", encoding="utf-8")
    lock = tmp_path / "rag-vet.lock"
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["pin", str(corpus), "--lock", str(lock)]).exit_code == 0
    data = json.loads(lock.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert len(data["documents"]) == 3
    assert all(v.startswith("sha256:") for v in data["documents"].values())

    (corpus / "a.md").write_text("second version", encoding="utf-8")
    (corpus / "c.md").unlink()
    (corpus / "d.md").write_text("new", encoding="utf-8")
    out = runner.invoke(app, ["scan", str(corpus), "--lock", str(lock), "-f", "json", "--fail-on", "medium"])
    assert out.exit_code == 1
    found = {(f["rule_id"], Path(f["path"]).name) for f in json.loads(out.output)["findings"]}
    assert found == {("RV401", "a.md"), ("RV402", "d.md"), ("RV403", "c.md")}


def test_bad_lockfile_is_rejected(tmp_path):
    lock = tmp_path / "bad.lock"
    lock.write_text(json.dumps({"version": 99, "documents": {}}), encoding="utf-8")
    out = runner.invoke(app, ["scan", str(CORPUS / "clean"), "--lock", str(lock)])
    assert out.exit_code == 2


def test_overlap_must_be_smaller_than_chunk_size():
    out = runner.invoke(app, ["scan", str(CORPUS / "clean"), "--chunk-size", "100", "--chunk-overlap", "100"])
    assert out.exit_code == 2


def test_rules_command_lists_every_rule():
    from rag_vet.rules import RULES

    out = runner.invoke(app, ["rules"])
    for rule_id in RULES:
        assert rule_id in out.output


def _repo_text_files():
    skip = {".git", "examples", "__pycache__", ".pytest_cache", ".ruff_cache"}
    for path in ROOT.rglob("*"):
        parts = set(path.relative_to(ROOT).parts)
        if parts & skip or not path.is_file() or path.suffix in {".pdf", ".docx", ".pyc"}:
            continue
        if any((p / "pyvenv.cfg").exists() for p in path.parents if ROOT in p.parents or p == ROOT):
            continue
        yield path


@pytest.mark.parametrize("path", list(_repo_text_files()), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_source_files_are_ascii(path):
    """Source and docs stay ASCII, so hidden characters cannot slip into the scanner itself."""
    data = path.read_bytes()
    assert all(b < 128 for b in data), f"non-ASCII byte in {path.relative_to(ROOT)}"


def test_corpus_rules_are_documented():
    from rag_vet.rules import RULES

    assert rules(scan([CORPUS], Options()).findings) <= set(RULES)
