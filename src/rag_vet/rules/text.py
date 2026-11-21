"""Detectors that work on plain text: injection phrasing, hidden Unicode, encoded payloads,
exfiltration URLs, secrets and personal data.

Each detector returns Hits with offsets into the text it was given, so the engine can map them
back to a line, a page and the chunks that would contain them.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from rag_vet.models import Severity


@dataclass
class Hit:
    rule_id: str
    start: int
    end: int
    evidence: str
    severity: Severity | None = None


INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore earlier instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|other|"
            r"system|original)\s+(instructions?|prompts?|rules|directions|guidelines|context)",
            re.I,
        ),
    ),
    (
        "addressed to the AI",
        re.compile(
            r"\b(note|message|instructions?|attention|reminder)\s+(to|for)\s+(the\s+|any\s+|all\s+)?"
            r"(ai|a\.i\.|llm|language\s+model|assistant|chatbot|ai\s+(?:assistant|agent|model)|model|agent)s?\s*[:,-]"
            r"|\bif\s+you\s+are\s+(an?\s+)?(ai|llm|large\s+language\s+model|language\s+model|ai\s+assistant|chatbot)\b"
            r"|\b(dear|hey|attention)\s+(ai|llm|assistant|chatbot|bot|gpt|copilot)\b",
            re.I,
        ),
    ),
    (
        "hide information from the user",
        re.compile(
            r"\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|notify|alert|show|disclose)\b[^.\n]{0,40}\buser\b"
            r"|\bwithout\s+(telling|informing|notifying|asking|alerting)\s+(the\s+)?user",
            re.I,
        ),
    ),
    (
        "hidden instruction block",
        re.compile(r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>", re.I),
    ),
    ("chat template tokens", re.compile(r"\[/?INST\]|<\|im_(start|end)\|>|<\|(system|user|assistant)\|>", re.I)),
    (
        "role reassignment",
        re.compile(
            r"\byou\s+are\s+now\s+(in\s+|a\s+|an\s+|the\s+)|\bnew\s+system\s+prompt\b|\bdeveloper\s+mode\b", re.I
        ),
    ),
    (
        "prompt extraction",
        re.compile(
            r"\b(reveal|print|output|repeat|leak|return|show)\s+(your\s+|the\s+)?(system\s+prompt|hidden\s+instructions|"
            r"initial\s+instructions)",
            re.I,
        ),
    ),
    (
        "answer override",
        re.compile(
            r"\b(when|whenever|if)\s+(the\s+)?(user|anyone|someone|they)\s+(asks?|queries|questions?)\b[^.\n]{0,80}"
            r"\b(always\s+)?(respond|answer|reply|say|tell\s+them|recommend)\b[^.\n]{0,20}\b(only|always|that|with)\b",
            re.I,
        ),
    ),
    (
        "covert behaviour",
        re.compile(
            r"\b(secretly|covertly)\s+\w+|\bsilently\s+(send|forward|copy|upload|include|exfiltrate|call|read|append)",
            re.I,
        ),
    ),
]

HIDDEN_CHARS = {
    **{cp: "ZERO WIDTH" for cp in (0x200B, 0x200C, 0x2060, 0x180E)},
    **{cp: "BIDI CONTROL" for cp in (0x202A, 0x202B, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069, 0x061C)},
    **{cp: "BIDI OVERRIDE" for cp in (0x202D, 0x202E)},
}

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,65536}={0,2}(?![A-Za-z0-9+/=])")

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    ("OpenAI-style API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>()\[\]`]+(?:\([^\s)]*\)[^\s\"'<>()\[\]`]*)*", re.I)
PLACEHOLDER_RE = re.compile(
    r"\{\{?[^{}/\s]{1,60}\}?\}|%7B%7B?|%7B[A-Za-z_]|<[A-Za-z_ ]{2,40}>|%3C[A-Za-z_]+%3E|\$\{?[A-Z][A-Z0-9_]{2,}"
    r"|\[(?:insert|add|put|include|data|secret|summary|conversation|chat|user)[^\]]*\]"
    r"|\b(?:INSERT|REPLACE|ADD)_?[A-Z_]{2,}|=(?:[A-Z]{2,}_)+[A-Z]{2,}\b"
)
IMAGE_BEFORE_RE = re.compile(r"!\[[^\]\n]*\]\(\s*<?$|<img\b[^>]*\bsrc\s*=\s*[\"']?$", re.I)

CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
EMAIL_DUMP = 20
_EXAMPLE_CARDS = {"4111111111111111", "4242424242424242", "5555555555554444", "378282246310005", "4000056655665556"}


def snippet(text: str, start: int, end: int, width: int = 50) -> str:
    lo, hi = max(0, start - width), min(len(text), end + width)
    s = re.sub(r"\s+", " ", text[lo:hi]).strip()
    s = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)
    return ("..." if lo else "") + s + ("..." if hi < len(text) else "")


def injection_matches(text: str) -> list[tuple[str, re.Match[str]]]:
    hits = []
    for label, pattern in INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append((label, m))
    return hits


def injections(text: str) -> list[Hit]:
    matches = injection_matches(text)
    if not matches:
        return []
    matches.sort(key=lambda lm: lm[1].start())
    labels = ", ".join(sorted({label for label, _ in matches}))
    first = matches[0][1]
    return [Hit("RV102", first.start(), first.end(), f"[{labels}] {snippet(text, first.start(), first.end())}")]


def _decode_tags(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def hidden_unicode(text: str) -> list[Hit]:
    """Tag characters and overrides are high severity; other invisible characters medium.

    A byte-order mark at the start, and zero-width joiners (used in emoji and many scripts), are allowed.
    Zero-width non-joiners and RTL/LTR marks next to letters are common in Persian, Arabic and Hebrew text,
    so they are only reported when there are many of them.
    """
    counts: dict[str, int] = {}
    first: int | None = None
    severe = False
    marks = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0xFEFF and i == 0:
            continue
        if cp in (0x200D, 0x00AD):
            continue
        if cp in (0x200E, 0x200F, 0x200C):
            marks += 1
            continue
        kind = HIDDEN_CHARS.get(cp)
        if kind is None and 0xE0000 <= cp <= 0xE007F:
            kind = "UNICODE TAG"
        if kind is None and unicodedata.category(ch) == "Cf":
            kind = "FORMAT CONTROL"
        if kind is None:
            continue
        severe = severe or kind in ("UNICODE TAG", "BIDI OVERRIDE")
        key = "U+E0000 block (UNICODE TAG)" if kind == "UNICODE TAG" else f"U+{cp:04X} ({kind})"
        counts[key] = counts.get(key, 0) + 1
        if first is None:
            first = i
    if marks > 50 and marks > len(text) // 20:
        counts["direction marks / ZWNJ"] = marks
    if not counts:
        return []
    evidence = ", ".join(f"{k} x{v}" for k, v in counts.items())
    decoded = _decode_tags(text)
    if decoded:
        evidence += f"; decoded tag text: {decoded[:120]!r}"
    pos = first or 0
    return [Hit("RV103", pos, pos + 1, evidence, Severity.HIGH if severe else Severity.MEDIUM)]


def _try_base64(blob: str) -> str | None:
    if not (re.search(r"[a-z]", blob) and re.search(r"[A-Z]", blob) and re.search(r"[0-9+/]", blob)):
        return None
    try:
        text = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.9 else None


def encoded_instructions(text: str) -> list[Hit]:
    for m in BASE64_RE.finditer(text):
        decoded = _try_base64(m.group(0))
        if decoded and injection_matches(decoded):
            return [Hit("RV104", m.start(), m.end(), f"base64 decodes to: {decoded[:120]!r}")]
    return []


DATA_WORDS = re.compile(
    r"conversation|chat|history|messages?|secret|summary|summari[sz]e|data|user|email|password|passwd|token|"
    r"api[_-]?key|credential|context|prompt|answer|query|memory|session|cookie|ssn|card",
    re.I,
)


def _is_exfil(url: str, image: bool) -> bool:
    """Images with any placeholder can leak data without a click. For links, a placeholder in the
    query or fragment, or one naming data (conversation, secret, ...), is required, so API
    documentation such as /repos/{owner}/{repo} is not reported."""
    rest = unquote(url.split("://", 1)[1] if "://" in url else url)
    found = [m.group(0) for m in PLACEHOLDER_RE.finditer(rest)]
    if not found:
        return False
    if image:
        return True
    query = re.split(r"[?#]", rest, maxsplit=1)[1] if re.search(r"[?#]", rest) else ""
    return bool(PLACEHOLDER_RE.search(query)) or any(DATA_WORDS.search(p) for p in found)


def _url_hit(url: str, start: int, end: int, image: bool) -> Hit:
    kind = "image" if image else "link"
    return Hit(
        "RV201",
        start,
        end,
        f"[{kind}] {snippet(url, 0, len(url), 0)[:200]}",
        Severity.HIGH if image else Severity.MEDIUM,
    )


def exfil_urls(text: str, extra_urls: list[tuple[str, bool]] | None = None) -> list[Hit]:
    """URLs with a fill-in placeholder. Markdown or HTML images are high severity."""
    hits: list[Hit] = []
    seen: set[str] = set()
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:")
        image = bool(IMAGE_BEFORE_RE.search(text[max(0, m.start() - 200) : m.start()]))
        if url in seen or not _is_exfil(url, image):
            continue
        seen.add(url)
        hits.append(_url_hit(url, m.start(), m.end(), image))
    for url, image in extra_urls or []:
        if url in seen or not url.lower().startswith(("http://", "https://")) or not _is_exfil(url, image):
            continue
        seen.add(url)
        hits.append(_url_hit(url, 0, 0, image))
    return hits


def secrets(text: str) -> list[Hit]:
    hits = []
    for label, pattern in SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append(Hit("RV301", m.start(), m.end(), f"[{label}] {m.group(0)[:6]}... (redacted)"))
    return hits


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        number = int("".join(str(int(c, 36)) for c in rearranged))
    except ValueError:
        return False
    return number % 97 == 1


def personal_data(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and len(set(digits)) > 2 and digits not in _EXAMPLE_CARDS and _luhn(digits):
            hits.append(Hit("RV302", m.start(), m.end(), f"[card number] ...{digits[-4:]} (redacted)"))
            break
    m = SSN_RE.search(text)
    if m and re.search(r"\b(ssn|social\s+security)\b", text[max(0, m.start() - 120) : m.end() + 40], re.I):
        hits.append(Hit("RV302", m.start(), m.end(), "[US social security number] ***-**-" + m.group(0)[-4:]))
    for m in IBAN_RE.finditer(text):
        if _iban_ok(m.group(0)):
            hits.append(Hit("RV302", m.start(), m.end(), f"[IBAN] {m.group(0)[:4]}... (redacted)"))
            break
    emails = {e.lower() for e in EMAIL_RE.findall(text) if not e.lower().endswith(("example.com", "example.org"))}
    if len(emails) >= EMAIL_DUMP:
        m = EMAIL_RE.search(text)
        if m:
            evidence = f"[email addresses] {len(emails)} distinct addresses"
            hits.append(Hit("RV302", m.start(), m.end(), evidence, Severity.LOW))
    return hits
