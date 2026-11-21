"""Corpus lockfile: a SHA-256 per document, so CI can tell what changed since the last review."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

LOCK_VERSION = 1


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def write(lock_path: Path, documents: dict[str, str]) -> None:
    doc = {"version": LOCK_VERSION, "tool": "rag-vet", "documents": dict(sorted(documents.items()))}
    lock_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")


def read(lock_path: Path) -> dict[str, str]:
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != LOCK_VERSION:
        raise ValueError(f"{lock_path}: unsupported lockfile version {data.get('version')!r}")
    documents = data.get("documents")
    if not isinstance(documents, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in documents.items()
    ):
        raise ValueError(f"{lock_path}: 'documents' must map paths to hashes")
    return documents
