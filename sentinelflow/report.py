"""Render a ``TriageReport`` as Markdown for humans (chat, tickets, postmortems)."""

from __future__ import annotations

from sentinelflow.models import HypothesisStatus, TriageReport, Verdict

_MARK = {Verdict.SUPPORTED: "PASS", Verdict.CONTRADICTED: "FAIL", Verdict.INCONCLUSIVE: "  ? "}


def to_markdown(report: TriageReport) -> str:
    lines = [
        f"# Incident triage: {report.service}",
        "",
        f"- **Incident:** `{report.incident_id}`",
        f"- **Detected:** {report.detected_at:%Y-%m-%d %H:%M} UTC",
        "- **Symptom onset:** "
        + (f"{report.symptom_onset:%Y-%m-%d %H:%M} UTC" if report.symptom_onset else "not established"),
        f"- **Attribution:** {report.attribution.value}",
        "",
        "## Summary",
        "",
        report.summary,
        "",
    ]

    if report.root_cause is not None:
        root = report.root_cause
        lines += [f"## Root cause: {root.title}", "", f"Confidence **{root.confidence:.2f}** ({root.status.value})", ""]
        lines += ["### Recommended remediation", ""]
        lines += [f"{n}. {step}" for n, step in enumerate(root.remediation, 1)]
        lines.append("")

    lines += ["## Hypotheses", "", "| Hypothesis | Origin | Confidence | Status |", "|---|---|---|---|"]
    for result in report.hypotheses:
        lines.append(f"| {result.title} | {result.origin} | {result.confidence:.2f} | {result.status.value} |")
    lines.append("")

    for result in report.hypotheses:
        if result.status is HypothesisStatus.REJECTED:
            continue
        lines += [f"### {result.title} - {result.confidence:.2f}", ""]
        if result.rationale:
            lines += [result.rationale, ""]
        lines += ["```"]
        for check in result.checks:
            cited = f" [{', '.join(check.evidence_ids)}]" if check.evidence_ids else ""
            required = " (required)" if check.required else ""
            lines.append(f"{_MARK[check.verdict]}  {check.name}{required}")
            lines.append(f"      {check.detail}{cited}")
        lines += ["```", ""]

    rejected = [r for r in report.hypotheses if r.status is HypothesisStatus.REJECTED]
    if rejected:
        lines += ["## Ruled out", ""]
        for result in rejected:
            reason = next((c.detail for c in result.checks if c.required), "required evidence missing")
            lines.append(f"- **{result.title}** - {reason}")
        lines.append("")

    if report.evidence_gaps:
        lines += ["## Evidence gaps", ""]
        lines += [f"- {gap}" for gap in report.evidence_gaps]
        lines.append("")

    if report.timeline:
        lines += ["## Timeline (UTC)", ""]
        for event in report.timeline:
            ref = f" `{event.evidence_id}`" if event.evidence_id else ""
            lines.append(f"- {event.at:%H:%M} - {event.description}{ref}")
        lines.append("")

    lines += ["## Evidence", "", "| Id | Source | Kind | Service | Observed | Summary |", "|---|---|---|---|---|---|"]
    for item in report.evidence:
        summary = item.summary.replace("|", "\\|")
        lines.append(
            f"| `{item.id}` | {item.source} | {item.kind} | {item.service} | {item.observed_at:%H:%M} | {summary} |"
        )
    lines.append("")
    return "\n".join(lines)
