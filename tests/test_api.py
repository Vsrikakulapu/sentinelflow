import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from sentinelflow.api import create_app  # noqa: E402
from sentinelflow.scenarios import generate  # noqa: E402
from sentinelflow.store import InMemoryStore  # noqa: E402


@pytest.fixture
def client():
    return TestClient(create_app(store=InMemoryStore()))


def body(kind, seed=0):
    return generate(kind, seed).model_dump(mode="json")


def test_health_endpoints(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json() == {"status": "ready"}


def test_triage_then_fetch_report_as_json_and_markdown(client):
    created = client.post("/incidents", json=body("db_connection_exhaustion"))
    assert created.status_code == 201
    report = created.json()
    assert report["attribution"] == "attributed"
    assert report["root_cause"]["id"] == "db_connection_exhaustion"
    assert report["root_cause"]["confidence"] >= 0.7

    incident_id = report["incident_id"]
    assert client.get(f"/incidents/{incident_id}").json() == report

    markdown = client.get(f"/incidents/{incident_id}/report.md")
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert "## Root cause: Database connection exhaustion" in markdown.text

    listing = client.get("/incidents").json()
    assert [(i["id"], i["root_cause"]) for i in listing] == [(incident_id, "db_connection_exhaustion")]


def test_unknown_incident_is_404(client):
    assert client.get("/incidents/nope").status_code == 404
    assert client.get("/incidents/nope/report.md").status_code == 404


def test_invalid_request_is_rejected(client):
    assert client.post("/incidents", json={"service": "x"}).status_code == 422
    payload = body("quiet")
    payload["lookback_minutes"] = 0
    assert client.post("/incidents", json=payload).status_code == 422


def test_recorded_deployments_are_used_as_evidence(client):
    payload = body("bad_deploy")
    deploys, payload["deploys"] = payload["deploys"], []
    without = client.post("/incidents", json=payload).json()
    assert without["root_cause"] is None

    for deploy in deploys:
        assert client.post("/deployments", json=deploy).status_code == 201
    assert client.post("/deployments", json=deploys[0]).status_code == 201  # re-delivery is idempotent

    with_history = client.post("/incidents", json=payload).json()
    assert with_history["root_cause"]["id"] == "bad_deploy"
    assert sum(e["kind"] == "deploy" for e in with_history["evidence"]) == sum(
        d["service"] in {"checkout-api", "payments-api", "inventory-api"} for d in deploys
    )


def test_scenario_endpoints_feed_the_triage_endpoint(client):
    assert "memory_leak" in client.get("/scenarios").json()["incidents"]
    scenario = client.get("/scenarios/memory_leak", params={"seed": 2})
    assert scenario.status_code == 200
    assert client.post("/incidents", json=scenario.json()).json()["root_cause"]["id"] == "memory_leak"
    assert client.get("/scenarios/not-a-scenario").status_code == 404


def test_database_probe_requires_configuration(client, monkeypatch):
    monkeypatch.delenv("SENTINELFLOW_TARGET_DATABASE_URL", raising=False)
    unconfigured = TestClient(create_app(store=InMemoryStore()))
    assert unconfigured.get("/database/health").status_code == 503
    assert unconfigured.post("/incidents", params={"probe_db": "true"}, json=body("quiet")).status_code == 503
