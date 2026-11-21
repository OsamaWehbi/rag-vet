"""Metadata for every rule. Detection logic lives in the sibling modules."""

from __future__ import annotations

from dataclasses import dataclass

from rag_vet.models import Severity

LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM04 = "LLM04:2025 Data and Model Poisoning"
LLM08 = "LLM08:2025 Vector and Embedding Weaknesses"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    owasp: str
    description: str
    remediation: str


_RULES = [
    # --- Hidden and injected content ------------------------------------------------
    Rule(
        "RV101",
        "Hidden text in document",
        Severity.MEDIUM,
        LLM01,
        "Text that a person reading the rendered document would not see, but that text extraction passes to the RAG "
        "index: display:none or white text in HTML, invisible, white, tiny or off-page text in PDF, hidden runs in "
        "Word, comments, alt text and metadata. Attackers use it to plant instructions that reviewers never see. "
        "Severity is high when the hidden text contains instructions or an exfiltration URL, and low for places that "
        "commonly hold harmless hidden text (comments, metadata, alt text, OCR layers).",
        "Open the document and check the hidden text. Remove it, or strip hidden content in your loader before "
        "indexing. `rag-vet extract --hidden FILE` prints exactly what is hidden and why.",
    ),
    Rule(
        "RV102",
        "Instructions aimed at the model",
        Severity.HIGH,
        LLM01,
        "Document text tries to steer the model that will read it after retrieval, for example telling it to ignore "
        "earlier instructions, address 'the AI assistant', hide information from the user or adopt a new role. This "
        "is indirect prompt injection.",
        "Remove the text, or exclude the document from the index. If it is a legitimate example (a security "
        "training page, say), ignore the rule for that path.",
    ),
    Rule(
        "RV103",
        "Hidden Unicode characters",
        Severity.HIGH,
        LLM01,
        "Unicode tag characters (which can carry invisible ASCII), bidirectional overrides or zero-width characters. "
        "They hide or reorder text for human readers while the model still reads it. Tag characters and overrides "
        "are high severity; other invisible characters are medium.",
        "Strip format characters (Unicode category Cf) during ingestion, keeping only those your languages need.",
    ),
    Rule(
        "RV104",
        "Encoded instructions",
        Severity.HIGH,
        LLM01,
        "A base64 string that decodes to instructions aimed at the model. Models decode base64 readily, so encoding "
        "is a way to slip instructions past keyword filters.",
        "Remove the encoded text and investigate where the document came from.",
    ),
    # --- Exfiltration ------------------------------------------------------------------
    Rule(
        "RV201",
        "Exfiltration URL template",
        Severity.HIGH,
        LLM02,
        "A URL with a placeholder such as {conversation}, {{secret}}, <DATA> or $VAR. If retrieved text asks the model "
        "to fill it in and render it, the chat client sends the data to that host, and a Markdown image does it "
        "without any click. Images are high severity, links medium.",
        "Remove the URL. In the application, do not render images or links to hosts outside an allowlist.",
    ),
    # --- Sensitive data ------------------------------------------------------------------
    Rule(
        "RV301",
        "Secret in document",
        Severity.HIGH,
        LLM02,
        "A private key or access token. Anything indexed can be retrieved by anyone who can query the RAG system, "
        "and often ends up in prompts sent to a third-party model. The evidence is redacted.",
        "Remove the secret from the document, rotate it, and add a secret scan to your ingestion pipeline.",
    ),
    Rule(
        "RV302",
        "Personal data in document",
        Severity.MEDIUM,
        LLM02,
        "Card numbers that pass the Luhn check, IBANs that pass the mod-97 check, US social security numbers, or a "
        "large number of email addresses. Indexing them exposes the data to every user of the RAG system. The "
        "evidence is redacted.",
        "Remove or mask the data before indexing, or restrict the index to users allowed to see it.",
    ),
    # --- Corpus integrity ------------------------------------------------------------
    Rule(
        "RV401",
        "Document changed since it was pinned",
        Severity.MEDIUM,
        LLM04,
        "The document's SHA-256 hash differs from the one in the lockfile, so it changed since it was last reviewed.",
        "Review the change, then run `rag-vet pin` to accept it.",
    ),
    Rule(
        "RV402",
        "Document not in the lockfile",
        Severity.LOW,
        LLM04,
        "A new document appeared in the corpus since the lockfile was written.",
        "Review the new document, then run `rag-vet pin` to accept it.",
    ),
    Rule(
        "RV403",
        "Pinned document is missing",
        Severity.INFO,
        LLM04,
        "A document in the lockfile is no longer in the corpus. This is usually a deliberate removal.",
        "Run `rag-vet pin` to update the lockfile.",
    ),
    Rule(
        "RV501",
        "Document could not be scanned",
        Severity.LOW,
        LLM08,
        "rag-vet could not parse the document (for example an encrypted or corrupt PDF), so nothing in it was checked. "
        "Your loader may still index it.",
        "Check the file. If your loader can read it, convert it to a format rag-vet supports, or exclude it.",
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}
