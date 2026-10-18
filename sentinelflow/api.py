"""FastAPI app for triaging incidents and storing reports."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse

from sentinelflow import __version__
from sentinelflow.collectors.db_health import PostgresHealthProbe
from sentinelflow.collectors.deploys import DEPLOY_LOOKBACK
from sentinelflow.hypotheses.llm import LLMClient, client_from_env
from sentinelflow.models import DbSnapshot, DeployRecord, TriageReport, TriageRequest
from sentinelflow.pipeline import triage
from sentinelflow.report import to_markdown
from sentinelflow.scenarios import NEGATIVE, POSITIVE, generate
from sentinelflow.store import IncidentSummary, Store, store_from_env


def probe_target_database(dsn: str) -> DbSnapshot:
    """Snapshot the monitored database (not SentinelFlow's own store)."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as connection:
        name = connection.info.dbname
        return PostgresHealthProbe(connection, database=name).snapshot()


def create_app(
    store: Store | None = None,
    llm: LLMClient | None = None,
    target_database_url: str | None = None,
) -> FastAPI:
    store = store if store is not None else store_from_env()
    llm = llm if llm is not None else client_from_env()
    target = target_database_url or os.getenv("SENTINELFLOW_TARGET_DATABASE_URL")

    app = FastAPI(
        title="SentinelFlow",
        version=__version__,
        description="Evidence-grounded failure triage and root-cause attribution.",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "store": store.name}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        if not store.ping():
            raise HTTPException(status_code=503, detail="store unavailable")
        return {"status": "ready"}

    @app.post("/deployments", status_code=201)
    def record_deployment(deploy: DeployRecord) -> DeployRecord:
        """Record a rollout (call this from CI/CD). Re-sending the same id is safe."""
        store.record_deploy(deploy)
        return deploy

    @app.get("/deployments")
    def list_deployments(
        service: str | None = None,
        hours: int = Query(default=24, ge=1, le=24 * 30),
    ) -> list[DeployRecord]:
        now = datetime.now(timezone.utc)
        return store.deploys({service} if service else None, now - timedelta(hours=hours), now)

    @app.get("/database/health")
    def database_health() -> DbSnapshot:
        """Live health snapshot of the monitored PostgreSQL instance."""
        if not target:
            raise HTTPException(status_code=503, detail="SENTINELFLOW_TARGET_DATABASE_URL is not configured")
        return probe_target_database(target)

    @app.post("/incidents", status_code=201)
    def create_incident(
        request: TriageRequest,
        probe_db: bool = Query(default=False, description="Add a live snapshot of the monitored database"),
    ) -> TriageReport:
        """Triage an incident and store the report."""
        known = {d.id for d in request.deploys}
        recorded = store.deploys(request.in_scope(), request.detected_at - DEPLOY_LOOKBACK, request.detected_at)
        request.deploys.extend(d for d in recorded if d.id not in known)

        if probe_db:
            if not target:
                raise HTTPException(status_code=503, detail="SENTINELFLOW_TARGET_DATABASE_URL is not configured")
            snapshot = probe_target_database(target)
            # A live probe describes the state at detection time for an ongoing incident.
            snapshot.captured_at = min(snapshot.captured_at, request.detected_at)
            request.db_snapshots.append(snapshot)

        report = triage(request, llm=llm, incident_id=str(uuid.uuid4()))
        store.save_report(report)
        return report

    @app.get("/incidents")
    def list_incidents(limit: int = Query(default=50, ge=1, le=500)) -> list[IncidentSummary]:
        return store.list_incidents(limit)

    def _report(incident_id: str) -> TriageReport:
        report = store.get_report(incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"incident {incident_id} not found")
        return report

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: str) -> TriageReport:
        return _report(incident_id)

    @app.get("/incidents/{incident_id}/report.md", response_class=PlainTextResponse)
    def get_incident_markdown(incident_id: str) -> PlainTextResponse:
        return PlainTextResponse(to_markdown(_report(incident_id)), media_type="text/markdown")

    @app.get("/scenarios")
    def list_scenarios() -> dict[str, list[str]]:
        return {"incidents": POSITIVE, "negative_controls": NEGATIVE}

    @app.get("/scenarios/{kind}")
    def get_scenario(kind: str, seed: int = 0) -> TriageRequest:
        """A synthetic incident bundle, ready to POST to /incidents."""
        try:
            return generate(kind, seed)
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    return app
