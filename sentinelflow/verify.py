"""Verification: turn check outcomes into a confidence score and an attribution.

The scoring is deliberately simple enough to explain in one paragraph:

    confidence = (supported weight - 1.5 x contradicted weight) / total weight

* a hypothesis whose *required* check is not supported is rejected outright
* contradiction costs more than support earns, because one fact that cannot be
  true under a hypothesis outweighs one fact that merely fits it
* support that comes from a single signal source is discounted by 20%:
  corroboration across logs / metrics / database / deploys is what makes an
  attribution trustworthy

A root cause is only *attributed* when the best hypothesis clears 0.60 and
beats the runner-up by 0.15. Otherwise the report says so and lists the
evidence that would settle it. Declining to name a cause is a valid result.
"""

from __future__ import annotations

from sentinelflow.evidence import EvidenceSet
from sentinelflow.hypotheses.catalog import CATALOG, Draft
from sentinelflow.models import (
    Attribution,
    CheckResult,
    HypothesisResult,
    HypothesisStatus,
    Verdict,
)

CONTRADICTION_PENALTY = 1.5
SINGLE_SOURCE_FACTOR = 0.8
CONFIRMED_AT = 0.70
PLAUSIBLE_AT = 0.40
ATTRIBUTION_MIN_CONFIDENCE = 0.60
ATTRIBUTION_MIN_MARGIN = 0.15


def score(checks: list[CheckResult], evidence: EvidenceSet) -> tuple[float, HypothesisStatus]:
    if not checks:
        return 0.0, HypothesisStatus.REJECTED
    if any(c.required and c.verdict is not Verdict.SUPPORTED for c in checks):
        return 0.0, HypothesisStatus.REJECTED

    total = sum(c.weight for c in checks)
    supported = sum(c.weight for c in checks if c.verdict is Verdict.SUPPORTED)
    contradicted = sum(c.weight for c in checks if c.verdict is Verdict.CONTRADICTED)
    confidence = (supported - CONTRADICTION_PENALTY * contradicted) / total

    sources = set()
    for check in checks:
        if check.verdict is Verdict.SUPPORTED:
            for evidence_id in check.evidence_ids:
                item = evidence.get(evidence_id)
                if item is not None:
                    sources.add(item.source)
    if len(sources) < 2:
        confidence *= SINGLE_SOURCE_FACTOR

    confidence = round(max(0.0, min(1.0, confidence)), 3)
    if confidence >= CONFIRMED_AT:
        return confidence, HypothesisStatus.CONFIRMED
    if confidence >= PLAUSIBLE_AT:
        return confidence, HypothesisStatus.PLAUSIBLE
    return confidence, HypothesisStatus.WEAK


def evaluate(draft: Draft, evidence: EvidenceSet) -> HypothesisResult:
    confidence, status = score(draft.checks, evidence)
    return HypothesisResult(
        id=draft.id,
        title=draft.title,
        confidence=confidence,
        status=status,
        rationale=draft.rationale,
        checks=draft.checks,
        remediation=draft.remediation if status is not HypothesisStatus.REJECTED else [],
    )


def verify_catalog(evidence: EvidenceSet) -> list[HypothesisResult]:
    return [evaluate(build(evidence), evidence) for build in CATALOG]


def rank(results: list[HypothesisResult]) -> list[HypothesisResult]:
    return sorted(results, key=lambda r: (-r.confidence, r.origin != "catalog", r.id))


def attribute(ranked: list[HypothesisResult]) -> tuple[Attribution, HypothesisResult | None]:
    """Decide whether the evidence singles out one root cause."""
    candidates = [r for r in ranked if r.origin == "catalog" and r.status is not HypothesisStatus.REJECTED]
    if not candidates or candidates[0].confidence < ATTRIBUTION_MIN_CONFIDENCE:
        return Attribution.INCONCLUSIVE, None
    best = candidates[0]
    runner_up = candidates[1].confidence if len(candidates) > 1 else 0.0
    if best.confidence - runner_up < ATTRIBUTION_MIN_MARGIN:
        return Attribution.AMBIGUOUS, best
    return Attribution.ATTRIBUTED, best


def evidence_gaps(ranked: list[HypothesisResult], attribution: Attribution) -> list[str]:
    """What is missing: the open checks on live hypotheses, or every unmet prerequisite."""
    live = [r for r in ranked if r.status is not HypothesisStatus.REJECTED]
    gaps: list[str] = []
    if live:
        limit = 1 if attribution is Attribution.ATTRIBUTED else 2
        for result in live[:limit]:
            for check in result.checks:
                if check.verdict is Verdict.INCONCLUSIVE:
                    gaps.append(f"{result.title}: {check.name} - {check.detail}")
    else:
        for result in ranked:
            for check in result.checks:
                if check.required:
                    gaps.append(f"{result.title}: {check.detail}")
    return gaps
