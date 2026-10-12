"""Evidence collectors.

Each collector turns one raw signal (logs, metrics, database health, deploy
history) into ``Evidence`` items. Collectors only *observe*: they never decide
what caused the incident. That separation is what lets the verification stage
test every hypothesis against the same, independently gathered facts.
"""

from __future__ import annotations

from sentinelflow.collectors.db_health import collect_db_health
from sentinelflow.collectors.deploys import collect_deploys
from sentinelflow.collectors.logs import collect_logs
from sentinelflow.collectors.metrics import collect_metrics
from sentinelflow.models import Evidence, TriageRequest

_PREFIX = {"logs": "log", "metrics": "met", "database": "db", "deploys": "dep"}


def collect_all(request: TriageRequest) -> list[Evidence]:
    """Run every collector and assign stable, human-readable evidence ids."""
    evidence: list[Evidence] = []
    for collector in (collect_logs, collect_metrics, collect_db_health, collect_deploys):
        evidence.extend(collector(request))
    evidence.sort(key=lambda e: (e.source, e.observed_at, e.kind, e.service, e.summary))
    counters: dict[str, int] = {}
    for item in evidence:
        counters[item.source] = counters.get(item.source, 0) + 1
        item.id = f"{_PREFIX[item.source]}-{counters[item.source]:02d}"
    return evidence


__all__ = [
    "collect_all",
    "collect_db_health",
    "collect_deploys",
    "collect_logs",
    "collect_metrics",
]
