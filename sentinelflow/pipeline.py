"""The triage pipeline: collect -> hypothesise -> verify -> attribute -> report."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sentinelflow.collectors import collect_all
from sentinelflow.evidence import EvidenceSet
from sentinelflow.hypotheses.llm import LLMClient, propose
from sentinelflow.models import (
    Attribution,
    Evidence,
    HypothesisResult,
    HypothesisStatus,
    TimelineEvent,
    TriageReport,
    TriageRequest,
    Verdict,
)
from sentinelflow.verify import attribute, evidence_gaps, rank, verify_catalog

_TIMELINE_KINDS = {
    "deploy", "error_spike", "metric_anomaly", "connection_saturation",
    "lock_contention", "new_error_signature", "metric_saturation",
}


def build_timeline(evidence: list[Evidence], request: TriageRequest) -> list[TimelineEvent]:
    events = [
        TimelineEvent(at=item.observed_at, description=item.summary, evidence_id=item.id)
        for item in evidence
        if item.kind in _TIMELINE_KINDS
    ]
    events.append(TimelineEvent(at=request.detected_at, description="Incident detected"))
    return sorted(events, key=lambda e: e.at)


def summarise(attribution: Attribution, root: HypothesisResult | None, ranked: list[HypothesisResult], evidence: EvidenceSet) -> str:
    rejected = [r.title for r in ranked if r.status is HypothesisStatus.REJECTED and r.origin == "catalog"]
    if len(evidence) == 0:
        return "No anomalous evidence was found in the logs, metrics, database or deploy history for this window."
    if root is None:
        return (
            "The evidence does not single out a root cause. "
            f"{len(evidence)} evidence item(s) were collected, but no hypothesis reached the "
            "confidence required for attribution. See the evidence gaps for what to check next."
        )
    supporting = [c for c in root.checks if c.verdict is Verdict.SUPPORTED]
    sources = sorted({item.source for i in root.evidence_ids if (item := evidence.get(i)) is not None})
    cited = ", ".join(root.evidence_ids[:6])
    text = (
        f"Most likely root cause: {root.title} (confidence {root.confidence:.2f}). "
        f"{len(supporting)} of {len(root.checks)} verification checks support it, "
        f"corroborated across {', '.join(sources)} [{cited}]."
    )
    if attribution is Attribution.AMBIGUOUS:
        alternatives = [r for r in ranked if r.id != root.id and r.status is not HypothesisStatus.REJECTED]
        if alternatives:
            text += (
                f" It is not clearly separated from '{alternatives[0].title}' "
                f"(confidence {alternatives[0].confidence:.2f}); treat both as open."
            )
    if rejected:
        text += f" Ruled out: {'; '.join(rejected)}."
    return text


def triage(
    request: TriageRequest,
    *,
    llm: LLMClient | None = None,
    incident_id: str | None = None,
    now: datetime | None = None,
) -> TriageReport:
    items = collect_all(request)
    evidence = EvidenceSet(items, request)

    results = verify_catalog(evidence)
    if llm is not None:
        results.extend(propose(llm, evidence))
    ranked = rank(results)
    attribution, root = attribute(ranked)

    return TriageReport(
        incident_id=incident_id or str(uuid.uuid4()),
        service=request.service,
        detected_at=request.detected_at,
        generated_at=now or datetime.now(timezone.utc),
        symptom_onset=evidence.symptom_onset,
        attribution=attribution,
        root_cause=root,
        summary=summarise(attribution, root, ranked, evidence),
        hypotheses=ranked,
        evidence=items,
        evidence_gaps=evidence_gaps(ranked, attribution),
        timeline=build_timeline(items, request),
    )
