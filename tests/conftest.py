import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from rag_vet.engine import Options, scan  # noqa: E402


@pytest.fixture
def scan_file(tmp_path):
    """Write content to a file in a temp dir and return the findings for it."""

    def run(name: str, content: str | bytes, **options):
        path = tmp_path / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return scan([path], Options(**options)).findings

    return run


def rules(findings) -> set[str]:
    return {f.rule_id for f in findings}
