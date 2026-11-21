# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `rag-vet scan` for Markdown, HTML, PDF, DOCX and plain-text documents, with table, JSON, SARIF 2.1.0 and Markdown
  output and a `--fail-on` threshold.
- Hidden-text extraction that separates what a reader sees from what a loader indexes, with the reason text is hidden:
  - HTML and Markdown: CSS hiding, white or transparent text, off-screen and clipped elements, comments, attributes,
    meta tags, link reference definitions and alt text.
  - PDF: render mode 3, white fill, tiny fonts, text outside the page, annotations and metadata, with OCR layers
    labelled.
  - DOCX: hidden font, white text, tiny fonts, tables, text boxes, headers, footers, comments and properties.
- Rules RV101 to RV104 (hidden text, instructions aimed at the model, hidden Unicode, encoded instructions), RV201
  (exfiltration URL templates), RV301 and RV302 (secrets and personal data, redacted), RV401 to RV403 (corpus
  lockfile) and RV501 (documents that could not be scanned).
- Chunk-aware findings: each finding lists the chunks that hold it, and says when it is split across chunks.
- `rag-vet extract` to show the visible and hidden text of a document, and `rag-vet pin` to write a corpus lockfile.
- GitHub Action, demo corpus of clean and poisoned documents, and a generated rules reference.
