from datetime import timedelta

import pytest
from conftest import at

from sentinelflow.bundle import load_bundle, write_bundle
from sentinelflow.evaluation import CONDITIONS, classify, withhold
from sentinelflow.models import Attribution, DeployRecord, HypothesisStatus, Verdict
from sentinelflow.pipeline import triage
from sentinelflow.report import to_markdown
from sentinelflow.scenarios import NEGATIVE, POSITIVE, expected_root_cause, generate

SEEDS = range(6)


@pytest.mark.parametrize("kind", POSITIVE)
@pytest.mark.parametrize("seed", SEEDS)
def test_each_failure_mode_is_attributed_to_its_true_cause(kind, seed):
    report = triage(generate(kind, seed))
    assert report.attribution is Attribution.ATTRIBUTED
    assert report.root_cause.id == kind
    assert report.root_cause.confidence >= 0.7
    assert report.root_cause.remediation


@pytest.mark.parametrize("kind", NEGATIVE)
@pytest.mark.parametrize("seed", SEEDS)
def test_negative_controls_are_not_attributed(kind, seed):
    report = triage(generate(kind, seed))
    assert report.attribution is Attribution.INCONCLUSIVE
    assert report.root_cause is None
    assert report.evidence_gaps


@pytest.mark.parametrize("condition", CONDITIONS)
@pytest.mark.parametrize("kind", POSITIVE + NEGATIVE)
def test_withholding_a_signal_source_never_causes_a_wrong_attribution(condition, kind):
    for seed in range(4):
        assert classify(withhold(generate(kind, seed), condition), expected_root_cause(kind)) != "wrong"


@pytest.mark.parametrize("kind", POSITIVE)
def test_every_citation_resolves_to_collected_evidence(kind):
    report = triage(generate(kind, 1))
    known = {item.id for item in report.evidence}
    assert len(known) == len(report.evidence)
    for hypothesis in report.hypotheses:
        for check in hypothesis.checks:
            assert set(check.evidence_ids) <= known
    assert set(report.root_cause.evidence_ids) <= known and report.root_cause.evidence_ids


def test_a_deploy_after_the_symptoms_began_is_not_blamed():
    request = generate("bad_deploy", 0)
    onset = triage(request).symptom_onset
    request.deploys = [DeployRecord(id="late", service=request.service, version="v9", deployed_at=onset + timedelta(minutes=6))]
    report = triage(request)
    bad_deploy = next(h for h in report.hypotheses if h.id == "bad_deploy")
    assert bad_deploy.status is HypothesisStatus.REJECTED
    assert next(c for c in bad_deploy.checks if c.required).verdict is Verdict.CONTRADICTED
    assert report.root_cause is None


def test_a_deploy_to_an_unrelated_service_is_not_blamed():
    request = generate("bad_deploy", 0)
    for deploy in request.deploys:
        deploy.service = "search-api"
    report = triage(request)
    assert all(e.kind != "deploy" for e in report.evidence)
    assert report.root_cause is None


def test_an_anomaly_that_predates_the_deploy_contradicts_it():
    request = generate("memory_leak", 0)
    onset = triage(request).symptom_onset
    request.deploys = [DeployRecord(id="d", service=request.service, version="v3", deployed_at=onset - timedelta(minutes=5))]
    report = triage(request)
    bad_deploy = next(h for h in report.hypotheses if h.id == "bad_deploy")
    ordering = next(c for c in bad_deploy.checks if c.name == "No anomaly predates the deployment")
    assert ordering.verdict is Verdict.CONTRADICTED
    assert report.root_cause.id == "memory_leak"


def test_upstream_failure_names_the_dependency_and_its_recent_deploy():
    for seed in range(10):
        request = generate("upstream_dependency_failure", seed)
        report = triage(request)
        assert "payments-api" in report.root_cause.title
        if any(d.service == "payments-api" for d in request.deploys):
            assert any("roll back" in step for step in report.root_cause.remediation)
            return
    pytest.fail("no seed produced a dependency deploy")


def test_empty_request_is_inconclusive_not_an_error(request_factory):
    report = triage(request_factory())
    assert report.attribution is Attribution.INCONCLUSIVE and report.evidence == []
    assert "No anomalous evidence" in report.summary


def test_markdown_report_cites_evidence_and_remediation():
    report = triage(generate("db_lock_contention", 0), incident_id="inc-1")
    text = to_markdown(report)
    assert "# Incident triage: checkout-api" in text
    assert "## Root cause: Database lock contention" in text
    assert "pid 4242" in text and "## Ruled out" in text
    for evidence_id in report.root_cause.evidence_ids:
        assert f"`{evidence_id}`" in text


def test_bundle_round_trip_gives_the_same_result(tmp_path):
    request = generate("traffic_overload", 3)
    write_bundle(request, tmp_path / "b", "traffic_overload")
    loaded = load_bundle(tmp_path / "b")
    first, second = triage(request, incident_id="x", now=at(0)), triage(loaded, incident_id="x", now=at(0))
    assert first.model_dump() == second.model_dump()


def test_bundle_with_missing_files_still_loads(tmp_path):
    write_bundle(generate("bad_deploy", 0), tmp_path / "b")
    (tmp_path / "b" / "db_snapshots.json").unlink()
    (tmp_path / "b" / "logs.jsonl").unlink()
    assert triage(load_bundle(tmp_path / "b")).root_cause.id == "bad_deploy"
