"""Persistence for triage reports and deployment history.

``PostgresStore`` is the production backend (reports as JSONB, evidence
denormalised into its own table so it can be queried across incidents).
``InMemoryStore`` implements the same interface for tests and local runs.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel

from sentinelflow.models import DeployRecord, TriageReport

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id            TEXT PRIMARY KEY,
    service       TEXT        NOT NULL,
    detected_at   TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    attribution   TEXT        NOT NULL,
    root_cause    TEXT,
    confidence    DOUBLE PRECISION,
    report        JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_service_detected ON incidents (service, detected_at DESC);

CREATE TABLE IF NOT EXISTS evidence (
    incident_id   TEXT        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    evidence_id   TEXT        NOT NULL,
    source        TEXT        NOT NULL,
    kind          TEXT        NOT NULL,
    service       TEXT        NOT NULL,
    observed_at   TIMESTAMPTZ NOT NULL,
    severity      DOUBLE PRECISION NOT NULL,
    summary       TEXT        NOT NULL,
    attributes    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (incident_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence (kind, observed_at DESC);

CREATE TABLE IF NOT EXISTS deployments (
    id            TEXT PRIMARY KEY,
    service       TEXT        NOT NULL,
    version       TEXT        NOT NULL,
    deployed_at   TIMESTAMPTZ NOT NULL,
    kind          TEXT        NOT NULL DEFAULT 'code',
    summary       TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_deployments_service_time ON deployments (service, deployed_at DESC);
"""


class IncidentSummary(BaseModel):
    id: str
    service: str
    detected_at: datetime
    attribution: str
    root_cause: str | None
    confidence: float | None


def summarise(report: TriageReport) -> IncidentSummary:
    return IncidentSummary(
        id=report.incident_id,
        service=report.service,
        detected_at=report.detected_at,
        attribution=report.attribution.value,
        root_cause=report.root_cause.id if report.root_cause else None,
        confidence=report.root_cause.confidence if report.root_cause else None,
    )


class Store(Protocol):
    name: str

    def ping(self) -> bool: ...
    def save_report(self, report: TriageReport) -> None: ...
    def get_report(self, incident_id: str) -> TriageReport | None: ...
    def list_incidents(self, limit: int = 50) -> list[IncidentSummary]: ...
    def record_deploy(self, deploy: DeployRecord) -> None: ...
    def deploys(self, services: set[str] | None, since: datetime, until: datetime) -> list[DeployRecord]: ...


class InMemoryStore:
    name = "memory"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reports: dict[str, TriageReport] = {}
        self._deploys: dict[str, DeployRecord] = {}

    def ping(self) -> bool:
        return True

    def save_report(self, report: TriageReport) -> None:
        with self._lock:
            self._reports[report.incident_id] = report

    def get_report(self, incident_id: str) -> TriageReport | None:
        return self._reports.get(incident_id)

    def list_incidents(self, limit: int = 50) -> list[IncidentSummary]:
        reports = sorted(self._reports.values(), key=lambda r: r.detected_at, reverse=True)
        return [summarise(r) for r in reports[:limit]]

    def record_deploy(self, deploy: DeployRecord) -> None:
        with self._lock:
            self._deploys[deploy.id] = deploy

    def deploys(self, services: set[str] | None, since: datetime, until: datetime) -> list[DeployRecord]:
        return sorted(
            (
                d
                for d in self._deploys.values()
                if (services is None or d.service in services) and since <= d.deployed_at <= until
            ),
            key=lambda d: d.deployed_at,
        )


class PostgresStore:
    name = "postgres"

    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._jsonb = Jsonb
        self._dsn = dsn
        with self._connect() as connection:
            connection.execute(SCHEMA)

    def _connect(self) -> Any:
        return self._psycopg.connect(self._dsn)

    def ping(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1")
            return True
        except self._psycopg.Error:
            return False

    def save_report(self, report: TriageReport) -> None:
        summary = summarise(report)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incidents (id, service, detected_at, attribution, root_cause, confidence, report)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    attribution = EXCLUDED.attribution,
                    root_cause  = EXCLUDED.root_cause,
                    confidence  = EXCLUDED.confidence,
                    report      = EXCLUDED.report
                """,
                (
                    summary.id, summary.service, summary.detected_at, summary.attribution,
                    summary.root_cause, summary.confidence, self._jsonb(report.model_dump(mode="json")),
                ),
            )
            connection.execute("DELETE FROM evidence WHERE incident_id = %s", (report.incident_id,))
            with connection.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO evidence (incident_id, evidence_id, source, kind, service,
                                          observed_at, severity, summary, attributes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            report.incident_id, item.id, item.source, item.kind, item.service,
                            item.observed_at, item.severity, item.summary, self._jsonb(item.attributes),
                        )
                        for item in report.evidence
                    ],
                )

    def get_report(self, incident_id: str) -> TriageReport | None:
        with self._connect() as connection:
            row = connection.execute("SELECT report FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        return TriageReport.model_validate(row[0]) if row else None

    def list_incidents(self, limit: int = 50) -> list[IncidentSummary]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, service, detected_at, attribution, root_cause, confidence
                FROM incidents ORDER BY detected_at DESC, id LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [
            IncidentSummary(id=r[0], service=r[1], detected_at=r[2], attribution=r[3], root_cause=r[4], confidence=r[5])
            for r in rows
        ]

    def record_deploy(self, deploy: DeployRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO deployments (id, service, version, deployed_at, kind, summary)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    service = EXCLUDED.service, version = EXCLUDED.version,
                    deployed_at = EXCLUDED.deployed_at, kind = EXCLUDED.kind, summary = EXCLUDED.summary
                """,
                (deploy.id, deploy.service, deploy.version, deploy.deployed_at, deploy.kind, deploy.summary),
            )

    def deploys(self, services: set[str] | None, since: datetime, until: datetime) -> list[DeployRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, service, version, deployed_at, kind, summary
                FROM deployments
                WHERE deployed_at BETWEEN %s AND %s
                  AND (%s::text[] IS NULL OR service = ANY(%s::text[]))
                ORDER BY deployed_at
                """,
                (since, until, sorted(services) if services is not None else None,
                 sorted(services) if services is not None else None),
            ).fetchall()
        return [
            DeployRecord(id=r[0], service=r[1], version=r[2], deployed_at=r[3], kind=r[4], summary=r[5])
            for r in rows
        ]


def store_from_env() -> Store:
    dsn = os.getenv("SENTINELFLOW_DATABASE_URL")
    return PostgresStore(dsn) if dsn else InMemoryStore()
