"""Regenerate docs/rules.md from the rule registry: python scripts/gen_rules_doc.py"""

from pathlib import Path

from rag_vet.rules import RULES

SECTIONS = {
    "RV1": "Hidden and injected content",
    "RV2": "Exfiltration",
    "RV3": "Sensitive data",
    "RV4": "Corpus integrity (needs --lock)",
    "RV5": "Coverage",
}

lines = [
    "# Rules",
    "",
    "Generated from `src/rag_vet/rules/registry.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.",
    "",
    "Severities are defaults. Some rules raise or lower severity depending on the evidence, as noted in the",
    "description. Skip a rule with `--ignore RV101`, or only for some paths with `--ignore RV102:docs/security/*`.",
    "",
    "| Rule | Severity | Title | OWASP |",
    "| --- | --- | --- | --- |",
]
lines += [f"| [{r.id}](#{r.id.lower()}) | {r.severity} | {r.title} | {r.owasp} |" for r in RULES.values()]
current = None
for r in RULES.values():
    section = SECTIONS[r.id[:3]]
    if section != current:
        lines += ["", f"## {section}"]
        current = section
    lines += [
        "",
        f"### {r.id}",
        "",
        f"**{r.title}** - default severity `{r.severity}` - {r.owasp}",
        "",
        r.description,
        "",
        f"**Remediation:** {r.remediation}",
    ]
Path(__file__).resolve().parent.parent.joinpath("docs", "rules.md").write_text(
    "\n".join(lines) + "\n", encoding="utf-8"
)
