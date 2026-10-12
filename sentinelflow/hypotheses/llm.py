"""Optional LLM stage: propose hypotheses the catalog does not cover.

The model is treated as an untrusted suggestion engine:

1. It only sees the collected evidence (ids, sources, summaries) - never raw logs.
2. Every hypothesis it returns must cite evidence ids. Citations that do not
   exist are dropped; a hypothesis left with fewer than two real citations is
   discarded as ungrounded.
3. Surviving hypotheses are verified with generic checks (grounding,
   cross-source corroboration, temporal order) and their confidence is capped
   below the attribution threshold. An LLM hypothesis can be reported as
   *plausible*; it can never be reported as the confirmed root cause.

Any OpenAI-compatible chat-completions endpoint works (OpenAI, Groq, Ollama,
vLLM). With no API key configured the stage is skipped and the pipeline is
fully deterministic.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Protocol

from sentinelflow.evidence import EvidenceSet
from sentinelflow.models import CheckResult, HypothesisResult, HypothesisStatus, Verdict

log = logging.getLogger(__name__)

LLM_CONFIDENCE_CAP = 0.55
MIN_CITATIONS = 2

SYSTEM_PROMPT = """You are an SRE assistant helping triage a production incident.
You are given evidence items, each with an id. Propose up to 3 root-cause hypotheses
that are NOT one of: bad deployment, database connection exhaustion, database lock
contention, memory leak, upstream dependency failure, traffic overload.
Only propose a hypothesis the evidence actually supports, and cite the evidence ids
it rests on. If nothing else is supported, return an empty list.
Respond with JSON only:
{"hypotheses": [{"title": str, "rationale": str, "evidence_ids": [str], "remediation": [str]}]}"""


class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatibleClient:
    """Minimal chat-completions client; works with any OpenAI-compatible API."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, system: str, user: str) -> str:
        import httpx

        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


def client_from_env() -> LLMClient | None:
    api_key = os.getenv("SENTINELFLOW_LLM_API_KEY")
    if not api_key:
        return None
    return OpenAICompatibleClient(
        base_url=os.getenv("SENTINELFLOW_LLM_BASE_URL", "https://api.openai.com/v1"),
        api_key=api_key,
        model=os.getenv("SENTINELFLOW_LLM_MODEL", "gpt-4o-mini"),
    )


def build_prompt(evidence: EvidenceSet) -> str:
    lines = [
        f"Affected service: {evidence.service}",
        f"Detected at: {evidence.request.detected_at.isoformat()}",
        f"Dependencies: {', '.join(evidence.dependencies) or 'none'}",
        "",
        "Evidence:",
    ]
    for item in evidence:
        lines.append(
            f"- [{item.id}] {item.observed_at:%H:%M} {item.source}/{item.kind} "
            f"({item.service}): {item.summary}"
        )
    return "\n".join(lines)


def _parse(raw: str) -> list[dict[str, Any]]:
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return []
    try:
        payload = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return []
    proposals = payload.get("hypotheses") if isinstance(payload, dict) else None
    return [p for p in proposals if isinstance(p, dict)] if isinstance(proposals, list) else []


def verify_proposal(proposal: dict[str, Any], index: int, evidence: EvidenceSet) -> HypothesisResult | None:
    title = str(proposal.get("title", "")).strip()
    cited = [str(i) for i in proposal.get("evidence_ids", []) if isinstance(i, (str, int))]
    real = [evidence.get(i) for i in dict.fromkeys(cited)]
    real = [item for item in real if item is not None]
    if not title or len(real) < MIN_CITATIONS:
        log.info("dropping ungrounded LLM hypothesis %r (%d valid citations)", title, len(real))
        return None

    real_ids = [item.id for item in real]
    invented = len(set(cited)) - len(real)
    sources = {item.source for item in real}
    onset = evidence.symptom_onset
    late = [item for item in real if onset is not None and item.source != "logs" and item.observed_at > onset]

    checks = [
        CheckResult(
            name="Every cited evidence item exists", weight=0.4, required=True,
            verdict=Verdict.SUPPORTED if invented == 0 else Verdict.CONTRADICTED,
            detail="All citations resolve to collected evidence." if invented == 0
            else f"{invented} cited id(s) do not exist in the evidence set.",
            evidence_ids=real_ids,
        ),
        CheckResult(
            name="Citations span independent signal sources", weight=0.3,
            verdict=Verdict.SUPPORTED if len(sources) >= 2 else Verdict.INCONCLUSIVE,
            detail=f"Cites {', '.join(sorted(sources))}.", evidence_ids=real_ids,
        ),
        CheckResult(
            name="Cited causes do not start after the symptoms", weight=0.3,
            verdict=Verdict.INCONCLUSIVE if onset is None
            else Verdict.CONTRADICTED if len(late) == len(real) else Verdict.SUPPORTED,
            detail="No symptom onset to compare against." if onset is None
            else f"{len(real) - len(late)} of {len(real)} cited items precede or coincide with onset.",
            evidence_ids=real_ids,
        ),
    ]
    supported = sum(c.weight for c in checks if c.verdict is Verdict.SUPPORTED)
    contradicted = sum(c.weight for c in checks if c.verdict is Verdict.CONTRADICTED)
    confidence = round(max(0.0, min(LLM_CONFIDENCE_CAP, LLM_CONFIDENCE_CAP * (supported - contradicted))), 3)
    if invented:
        status = HypothesisStatus.REJECTED
        confidence = 0.0
    else:
        status = HypothesisStatus.PLAUSIBLE if confidence >= 0.4 else HypothesisStatus.WEAK
    remediation = [str(step) for step in proposal.get("remediation", []) if isinstance(step, str)][:5]
    return HypothesisResult(
        id=f"llm_{index + 1}",
        title=title[:160],
        origin="llm",
        confidence=confidence,
        status=status,
        rationale=str(proposal.get("rationale", ""))[:600],
        checks=checks,
        remediation=remediation if status is not HypothesisStatus.REJECTED else [],
    )


def propose(client: LLMClient, evidence: EvidenceSet) -> list[HypothesisResult]:
    """Ask the model for extra hypotheses; never let a model failure fail the triage."""
    if len(evidence) == 0:
        return []
    try:
        raw = client.complete(SYSTEM_PROMPT, build_prompt(evidence))
    except Exception:  # noqa: BLE001 - the LLM stage is best-effort by design
        log.warning("LLM hypothesis stage failed; continuing without it", exc_info=True)
        return []
    results = []
    for index, proposal in enumerate(_parse(raw)[:3]):
        result = verify_proposal(proposal, index, evidence)
        if result is not None:
            results.append(result)
    return results
