# Security Policy

rag-vet is a security tool that reads untrusted documents, so its own behaviour matters. This document explains how
to report a vulnerability, what rag-vet does when it scans, and its known limitations.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/OsamaWehbi/rag-vet/security/advisories/new) on this repository.
You can expect an acknowledgement within 72 hours.

Useful reports include: a crafted document that crashes or hangs rag-vet, a way to make it read files or contact
hosts it should not, or a reliable way to hide text from a rule that is not already listed under known limitations.

## What rag-vet does when it scans

- It reads the files you point it at and nothing else. Symbolic links inside a scanned directory are not followed.
- It never executes document content: no scripts, macros, embedded files or external references.
- It makes no network connections. URLs in documents are reported, never fetched.
- Reports contain short evidence snippets of the offending text. Secrets and personal data are redacted, but other
  snippets quote the document, so treat reports from private corpora as sensitive.

## Threat model (summary)

| Threat | Control |
|---|---|
| Hostile document crashes the scan | Each document is parsed in isolation; a parse failure becomes an RV501 finding and the scan continues |
| Very large documents exhaust memory or time | Files over `--max-file-size` (50 MB by default) are skipped and listed; each document is scanned up to 5 million characters |
| Deeply nested or malformed HTML slows the parser | Inherited style state is stored per element and stray end tags are skipped, so parsing stays linear at any depth |
| XML external entities in DOCX | python-docx parses XML with entity resolution disabled |
| Hidden characters hide evidence from the reviewer | Evidence escapes non-printable characters; Unicode tag text is decoded and shown |
| Terminal escape sequences in document text | Rich markup is escaped and control characters are shown as `\uXXXX` |
| Report injection into Markdown summaries | Table separators and backticks are escaped |
| Shell injection through the GitHub Action inputs | Inputs are passed as environment variables and split into an argument array, never interpolated into the script |

## Known limitations

- Detection is heuristic. A clean report means no known technique was found, not that a document is safe.
- rag-vet does not render documents. Text covered by images or shapes, and styles applied by complex CSS selectors,
  are not detected. PDF white text is judged against a white page.
- Images are not scanned, so instructions inside pictures are missed.
- Compressed formats (DOCX, compressed PDF streams) are limited by file size before decompression. For corpora from
  untrusted sources, run rag-vet in a container or a throwaway VM with memory limits.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
