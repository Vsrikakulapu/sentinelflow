"""Shared data models.

Everything the pipeline produces is one of these types, so a report can be
serialised to JSON, stored in PostgreSQL and rendered to Markdown without
losing the link between a conclusion and the evidence it rests on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Source = Literal["logs", "metrics", "database", "deploys"]


def as_utc(value: datetime) -> datetime:
    """Normalise a datetime to timezone-aware UTC (naive values are taken as UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------- inputs


class LogRecord(BaseModel):
    ts: datetime
    service: str
    level: str = "INFO"
    message: str

    _utc = field_validator("ts")(as_utc)


class MetricSeries(BaseModel):
    """One time series. ``points`` are ``[timestamp, value]`` pairs in time order."""

    name: str
    service: str
    limit: float | None = None
    points: list[tuple[datetime, float]]

    @field_validator("points")
    @classmethod
    def _points_utc(cls, points: list[tuple[datetime, float]]) -> list[tuple[datetime, float]]:
        return sorted((as_utc(ts), value) for ts, value in points)


class LongRunningQuery(BaseModel):
    pid: int
    duration_s: float
    state: str = "active"
    query: str = ""
    wait_event_type: str | None = None


class BlockedQuery(BaseModel):
    blocked_pid: int
    blocking_pid: int
    blocked_duration_s: float
    lock_type: str = "relation"
    relation: str = ""
    blocking_query: str = ""


class DbSnapshot(BaseModel):
    """Point-in-time health of a PostgreSQL instance (see ``collectors.db_health``)."""

    captured_at: datetime
    database: str = "postgres"
    max_connections: int
    active: int = 0
    idle: int = 0
    idle_in_transaction: int = 0
    waiting_on_lock: int = 0
    long_running_queries: list[LongRunningQuery] = []
    blocked_queries: list[BlockedQuery] = []
    deadlocks_total: int = 0
    replication_lag_s: float | None = None

    _utc = field_validator("captured_at")(as_utc)

    @property
    def connections_used(self) -> int:
        return self.active + self.idle + self.idle_in_transaction


class DeployRecord(BaseModel):
    id: str
    service: str
    version: str
    deployed_at: datetime
    kind: Literal["code", "config", "migration", "infra"] = "code"
    summary: str = ""

    _utc = field_validator("deployed_at")(as_utc)


class TriageRequest(BaseModel):
    """Everything needed to triage one incident."""

    service: str = Field(description="Service the alert fired for")
    detected_at: datetime = Field(description="When the incident was detected")
    lookback_minutes: int = Field(default=30, ge=5, le=24 * 60)
    topology: dict[str, list[str]] = Field(
        default_factory=dict, description="service -> services it depends on"
    )
    logs: list[LogRecord] = []
    metrics: list[MetricSeries] = []
    db_snapshots: list[DbSnapshot] = []
    deploys: list[DeployRecord] = []

    _utc = field_validator("detected_at")(as_utc)

    @property
    def window_start(self) -> datetime:
        return self.detected_at - timedelta(minutes=self.lookback_minutes)

    def dependencies(self) -> list[str]:
        """Transitive dependencies of the affected service, nearest first."""
        seen: list[str] = []
        frontier = list(self.topology.get(self.service, []))
        while frontier:
            dep = frontier.pop(0)
            if dep == self.service or dep in seen:
                continue
            seen.append(dep)
            frontier.extend(self.topology.get(dep, []))
        return seen

    def in_scope(self) -> set[str]:
        return {self.service, *self.dependencies()}


# ------------------------------------------------------------------------- evidence


class Evidence(BaseModel):
    """One observed fact. Every claim in a report cites evidence by ``id``."""

    id: str
    source: Source
    kind: str
    service: str
    observed_at: datetime
    summary: str
    severity: float = Field(ge=0.0, le=1.0)
    attributes: dict[str, Any] = {}


# -------------------------------------------------------------------- verification


class Verdict(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    INCONCLUSIVE = "inconclusive"


class CheckResult(BaseModel):
    """Outcome of testing one prediction of a hypothesis against the evidence."""

    name: str
    verdict: Verdict
    weight: float
    required: bool = False
    detail: str
    evidence_ids: list[str] = []


class HypothesisStatus(StrEnum):
    CONFIRMED = "confirmed"
    PLAUSIBLE = "plausible"
    WEAK = "weak"
    REJECTED = "rejected"


class HypothesisResult(BaseModel):
    id: str
    title: str
    origin: Literal["catalog", "llm"] = "catalog"
    confidence: float = Field(ge=0.0, le=1.0)
    status: HypothesisStatus
    rationale: str = ""
    checks: list[CheckResult] = []
    remediation: list[str] = []

    @property
    def evidence_ids(self) -> list[str]:
        ids: list[str] = []
        for check in self.checks:
            if check.verdict is Verdict.SUPPORTED:
                ids.extend(i for i in check.evidence_ids if i not in ids)
        return ids


class Attribution(StrEnum):
    ATTRIBUTED = "attributed"
    AMBIGUOUS = "ambiguous"
    INCONCLUSIVE = "inconclusive"


class TimelineEvent(BaseModel):
    at: datetime
    description: str
    evidence_id: str | None = None


class TriageReport(BaseModel):
    incident_id: str
    service: str
    detected_at: datetime
    generated_at: datetime
    symptom_onset: datetime | None
    attribution: Attribution
    root_cause: HypothesisResult | None
    summary: str
    hypotheses: list[HypothesisResult]
    evidence: list[Evidence]
    evidence_gaps: list[str] = []
    timeline: list[TimelineEvent] = []
