# Rules

Generated from `src/rag_vet/rules/registry.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.

Severities are defaults. Some rules raise or lower severity depending on the evidence, as noted in the
description. Skip a rule with `--ignore RV101`, or only for some paths with `--ignore RV102:docs/security/*`.

| Rule | Severity | Title | OWASP |
| --- | --- | --- | --- |
| [RV101](#rv101) | medium | Hidden text in document | LLM01:2025 Prompt Injection |
| [RV102](#rv102) | high | Instructions aimed at the model | LLM01:2025 Prompt Injection |
| [RV103](#rv103) | high | Hidden Unicode characters | LLM01:2025 Prompt Injection |
| [RV104](#rv104) | high | Encoded instructions | LLM01:2025 Prompt Injection |
| [RV201](#rv201) | high | Exfiltration URL template | LLM02:2025 Sensitive Information Disclosure |
| [RV301](#rv301) | high | Secret in document | LLM02:2025 Sensitive Information Disclosure |
| [RV302](#rv302) | medium | Personal data in document | LLM02:2025 Sensitive Information Disclosure |
| [RV401](#rv401) | medium | Document changed since it was pinned | LLM04:2025 Data and Model Poisoning |
| [RV402](#rv402) | low | Document not in the lockfile | LLM04:2025 Data and Model Poisoning |
| [RV403](#rv403) | info | Pinned document is missing | LLM04:2025 Data and Model Poisoning |
| [RV501](#rv501) | low | Document could not be scanned | LLM08:2025 Vector and Embedding Weaknesses |

## Hidden and injected content

### RV101

**Hidden text in document** - default severity `medium` - LLM01:2025 Prompt Injection

Text that a person reading the rendered document would not see, but that text extraction passes to the RAG index: display:none or white text in HTML, invisible, white, tiny or off-page text in PDF, hidden runs in Word, comments, alt text and metadata. Attackers use it to plant instructions that reviewers never see. Severity is high when the hidden text contains instructions or an exfiltration URL, and low for places that commonly hold harmless hidden text (comments, metadata, alt text, OCR layers).

**Remediation:** Open the document and check the hidden text. Remove it, or strip hidden content in your loader before indexing. `rag-vet extract --hidden FILE` prints exactly what is hidden and why.

### RV102

**Instructions aimed at the model** - default severity `high` - LLM01:2025 Prompt Injection

Document text tries to steer the model that will read it after retrieval, for example telling it to ignore earlier instructions, address 'the AI assistant', hide information from the user or adopt a new role. This is indirect prompt injection.

**Remediation:** Remove the text, or exclude the document from the index. If it is a legitimate example (a security training page, say), ignore the rule for that path.

### RV103

**Hidden Unicode characters** - default severity `high` - LLM01:2025 Prompt Injection

Unicode tag characters (which can carry invisible ASCII), bidirectional overrides or zero-width characters. They hide or reorder text for human readers while the model still reads it. Tag characters and overrides are high severity; other invisible characters are medium.

**Remediation:** Strip format characters (Unicode category Cf) during ingestion, keeping only those your languages need.

### RV104

**Encoded instructions** - default severity `high` - LLM01:2025 Prompt Injection

A base64 string that decodes to instructions aimed at the model. Models decode base64 readily, so encoding is a way to slip instructions past keyword filters.

**Remediation:** Remove the encoded text and investigate where the document came from.

## Exfiltration

### RV201

**Exfiltration URL template** - default severity `high` - LLM02:2025 Sensitive Information Disclosure

A URL with a placeholder such as {conversation}, {{secret}}, <DATA> or $VAR. If retrieved text asks the model to fill it in and render it, the chat client sends the data to that host, and a Markdown image does it without any click. Images are high severity, links medium.

**Remediation:** Remove the URL. In the application, do not render images or links to hosts outside an allowlist.

## Sensitive data

### RV301

**Secret in document** - default severity `high` - LLM02:2025 Sensitive Information Disclosure

A private key or access token. Anything indexed can be retrieved by anyone who can query the RAG system, and often ends up in prompts sent to a third-party model. The evidence is redacted.

**Remediation:** Remove the secret from the document, rotate it, and add a secret scan to your ingestion pipeline.

### RV302

**Personal data in document** - default severity `medium` - LLM02:2025 Sensitive Information Disclosure

Card numbers that pass the Luhn check, IBANs that pass the mod-97 check, US social security numbers, or a large number of email addresses. Indexing them exposes the data to every user of the RAG system. The evidence is redacted.

**Remediation:** Remove or mask the data before indexing, or restrict the index to users allowed to see it.

## Corpus integrity (needs --lock)

### RV401

**Document changed since it was pinned** - default severity `medium` - LLM04:2025 Data and Model Poisoning

The document's SHA-256 hash differs from the one in the lockfile, so it changed since it was last reviewed.

**Remediation:** Review the change, then run `rag-vet pin` to accept it.

### RV402

**Document not in the lockfile** - default severity `low` - LLM04:2025 Data and Model Poisoning

A new document appeared in the corpus since the lockfile was written.

**Remediation:** Review the new document, then run `rag-vet pin` to accept it.

### RV403

**Pinned document is missing** - default severity `info` - LLM04:2025 Data and Model Poisoning

A document in the lockfile is no longer in the corpus. This is usually a deliberate removal.

**Remediation:** Run `rag-vet pin` to update the lockfile.

## Coverage

### RV501

**Document could not be scanned** - default severity `low` - LLM08:2025 Vector and Embedding Weaknesses

rag-vet could not parse the document (for example an encrypted or corrupt PDF), so nothing in it was checked. Your loader may still index it.

**Remediation:** Check the file. If your loader can read it, convert it to a format rag-vet supports, or exclude it.
