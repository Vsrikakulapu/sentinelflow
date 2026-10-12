"""Query helper over collected evidence, shared by all hypothesis checks."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timedelta

from sentinelflow.models import Evidence, TriageRequest

SYMPTOM_METRICS = {"latency_p99_ms", "latency_p95_ms", "error_rate"}


class EvidenceSet:
    def __init__(self, items: Iterable[Evidence], request: TriageRequest) -> None:
        self.items = list(items)
        self.request = request
        self.service = request.service
        self.dependencies = request.dependencies()
        self._by_id = {item.id: item for item in self.items}

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def get(self, evidence_id: str) -> Evidence | None:
        return self._by_id.get(evidence_id)

    def find(
        self,
        *,
        kind: str | tuple[str, ...] | None = None,
        source: str | None = None,
        service: str | Iterable[str] | None = None,
        where: Callable[[Evidence], bool] | None = None,
    ) -> list[Evidence]:
        kinds = (kind,) if isinstance(kind, str) else kind
        services = {service} if isinstance(service, str) else set(service) if service else None
        return [
            item
            for item in self.items
            if (kinds is None or item.kind in kinds)
            and (source is None or item.source == source)
            and (services is None or item.service in services)
            and (where is None or where(item))
        ]

    def metric(self, name_prefix: str, *, service: str | None = None, kind: str | tuple[str, ...] = "metric_anomaly", direction: str | None = "up") -> list[Evidence]:
        def matches(item: Evidence) -> bool:
            if not str(item.attributes.get("metric", "")).startswith(name_prefix):
                return False
            return direction is None or item.attributes.get("direction", direction) == direction

        return self.find(kind=kind, service=service or self.service, where=matches)

    def log_category(self, category: str, *, service: str | None = None) -> list[Evidence]:
        return self.find(
            kind=("new_error_signature", "error_signature_surge"),
            service=service or self.service,
            where=lambda item: item.attributes.get("category") == category,
        )

    def symptoms(self, service: str | None = None) -> list[Evidence]:
        """User-visible degradation: error spikes and latency / error-rate anomalies."""
        target = service or self.service
        return self.find(kind="error_spike", service=target) + self.find(
            kind="metric_anomaly",
            service=target,
            where=lambda item: item.attributes.get("metric") in SYMPTOM_METRICS
            and item.attributes.get("direction") == "up",
        )

    @property
    def symptom_onset(self) -> datetime | None:
        """Earliest moment the affected service visibly degraded."""
        return earliest(self.symptoms())

    def self_deploy_near_onset(self, within: timedelta = timedelta(minutes=45)) -> list[Evidence]:
        onset = self.symptom_onset or self.request.detected_at
        return self.find(
            kind="deploy",
            service=self.service,
            where=lambda item: onset - within <= item.observed_at <= onset + timedelta(minutes=3),
        )


def earliest(items: Iterable[Evidence]) -> datetime | None:
    return min((item.observed_at for item in items), default=None)


def ids(items: Iterable[Evidence]) -> list[str]:
    return [item.id for item in items]
