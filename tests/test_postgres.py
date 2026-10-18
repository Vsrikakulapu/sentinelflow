"""Integration tests against a real PostgreSQL."""

import os
import threading
import time
from datetime import timedelta

import pytest
from conftest import at

DSN = os.getenv("SENTINELFLOW_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="SENTINELFLOW_TEST_DATABASE_URL not set")

psycopg = pytest.importorskip("psycopg") if DSN else None

from sentinelflow.collectors.db_health import PostgresHealthProbe  # noqa: E402
from sentinelflow.models import DeployRecord  # noqa: E402
from sentinelflow.pipeline import triage  # noqa: E402
from sentinelflow.scenarios import generate  # noqa: E402
from sentinelflow.store import PostgresStore  # noqa: E402


@pytest.fixture
def store():
    store = PostgresStore(DSN)
    with psycopg.connect(DSN) as connection:
        connection.execute("TRUNCATE incidents, evidence, deployments")
    return store


def test_schema_creation_is_idempotent(store):
    PostgresStore(DSN)
    assert store.ping()


def test_report_round_trips_through_jsonb(store):
    report = triage(generate("db_lock_contention", 1))
    store.save_report(report)
    assert store.get_report(report.incident_id) == report
    assert store.get_report("missing") is None

    with psycopg.connect(DSN) as connection:
        rows = connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE source = 'database') FROM evidence WHERE incident_id = %s",
            (report.incident_id,),
        ).fetchone()
    assert rows[0] == len(report.evidence) and rows[1] >= 1

    store.save_report(report)  # saving again replaces, never duplicates
    [summary] = store.list_incidents()
    assert (summary.id, summary.root_cause, summary.attribution) == (report.incident_id, "db_lock_contention", "attributed")


def test_deploy_history_is_upserted_and_filtered(store):
    store.record_deploy(DeployRecord(id="d1", service="checkout-api", version="v1", deployed_at=at(-30)))
    store.record_deploy(DeployRecord(id="d1", service="checkout-api", version="v1.1", deployed_at=at(-30)))
    store.record_deploy(DeployRecord(id="d2", service="search-api", version="v7", deployed_at=at(-20), kind="config"))
    window = (at(-60), at(0))
    assert [d.version for d in store.deploys({"checkout-api"}, *window)] == ["v1.1"]
    assert [d.id for d in store.deploys(None, *window)] == ["d1", "d2"]
    assert store.deploys({"checkout-api"}, at(-10), at(0)) == []


def test_probe_reads_a_live_database():
    with psycopg.connect(DSN, autocommit=True) as connection:
        snapshot = PostgresHealthProbe(connection, database="live").snapshot()
    assert snapshot.max_connections > 0
    assert snapshot.connections_used <= snapshot.max_connections
    assert snapshot.blocked_queries == []


def test_probe_detects_real_lock_contention_and_names_the_blocker():
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute("DROP TABLE IF EXISTS sf_lock_probe")
        admin.execute("CREATE TABLE sf_lock_probe (id int PRIMARY KEY, v int)")
        admin.execute("INSERT INTO sf_lock_probe VALUES (1, 0)")

    holder = psycopg.connect(DSN)
    holder.execute("UPDATE sf_lock_probe SET v = v + 1 WHERE id = 1")  # row lock held, transaction open

    def waiter():
        try:
            with psycopg.connect(DSN) as connection:
                connection.execute("SET lock_timeout = '10s'")
                connection.execute("UPDATE sf_lock_probe SET v = v + 1 WHERE id = 1")
        except psycopg.Error:
            pass

    thread = threading.Thread(target=waiter)
    thread.start()
    try:
        snapshot = None
        with psycopg.connect(DSN, autocommit=True) as connection:
            probe = PostgresHealthProbe(connection, database="live")
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                snapshot = probe.snapshot(long_query_seconds=0)
                if snapshot.blocked_queries:
                    break
                time.sleep(0.1)
        assert snapshot.blocked_queries, "probe never saw the blocked UPDATE"
        assert snapshot.blocked_queries[0].blocking_pid == holder.info.backend_pid
        assert snapshot.waiting_on_lock >= 1
        assert any(q.pid == holder.info.backend_pid for q in snapshot.long_running_queries)
    finally:
        holder.rollback()
        holder.close()
        thread.join(timeout=15)


def test_live_snapshot_flows_into_triage():
    """A real saturated-looking snapshot is analysed exactly like a replayed one."""
    with psycopg.connect(DSN, autocommit=True) as connection:
        snapshot = PostgresHealthProbe(connection, database="orders-db").snapshot()
    request = generate("quiet", 0)
    snapshot.captured_at = request.detected_at - timedelta(minutes=1)
    snapshot.idle_in_transaction = snapshot.max_connections  # simulate a leak on top of the real reading
    request.db_snapshots.append(snapshot)
    kinds = {e.kind for e in triage(request).evidence}
    assert {"connection_saturation", "idle_in_transaction"} <= kinds


def test_api_persists_to_postgres(store):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from sentinelflow.api import create_app

    client = TestClient(create_app(store=store, target_database_url=DSN))
    health = client.get("/database/health")
    assert health.status_code == 200 and health.json()["max_connections"] > 0

    created = client.post("/incidents", params={"probe_db": "true"}, json=generate("traffic_overload", 0).model_dump(mode="json"))
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]
    assert store.get_report(incident_id).root_cause.id == "traffic_overload"
    assert client.get(f"/incidents/{incident_id}/report.md").status_code == 200
