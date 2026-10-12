from conftest import at

from sentinelflow.evidence import EvidenceSet
from sentinelflow.models import Attribution, CheckResult, Evidence, HypothesisResult, HypothesisStatus, Verdict
from sentinelflow.verify import attribute, evidence_gaps, rank, score


def ev(evidence_id, source):
    return Evidence(id=evidence_id, source=source, kind="k", service="s", observed_at=at(0), summary="", severity=0.5)


def check(verdict, weight, ids=(), required=False):
    return CheckResult(name="c", verdict=verdict, weight=weight, required=required, detail="d", evidence_ids=list(ids))


def evidence_set(request_factory):
    return EvidenceSet([ev("log-01", "logs"), ev("met-01", "metrics")], request_factory())


def test_unmet_required_check_rejects_the_hypothesis(request_factory):
    checks = [check(Verdict.INCONCLUSIVE, 0.3, required=True), check(Verdict.SUPPORTED, 0.7, ["log-01", "met-01"])]
    assert score(checks, evidence_set(request_factory)) == (0.0, HypothesisStatus.REJECTED)


def test_full_cross_source_support_is_confirmed(request_factory):
    checks = [check(Verdict.SUPPORTED, 0.4, ["log-01"], required=True), check(Verdict.SUPPORTED, 0.6, ["met-01"])]
    assert score(checks, evidence_set(request_factory)) == (1.0, HypothesisStatus.CONFIRMED)


def test_single_source_support_is_discounted(request_factory):
    checks = [check(Verdict.SUPPORTED, 0.4, ["log-01"], required=True), check(Verdict.SUPPORTED, 0.6, ["log-01"])]
    assert score(checks, evidence_set(request_factory)) == (0.8, HypothesisStatus.CONFIRMED)


def test_contradiction_costs_more_than_support_earns(request_factory):
    checks = [
        check(Verdict.SUPPORTED, 0.5, ["log-01"], required=True),
        check(Verdict.SUPPORTED, 0.2, ["met-01"]),
        check(Verdict.CONTRADICTED, 0.3, ["met-01"]),
    ]
    confidence, status = score(checks, evidence_set(request_factory))
    assert confidence == 0.25 and status is HypothesisStatus.WEAK


def result(hid, confidence, origin="catalog"):
    status = HypothesisStatus.REJECTED if confidence == 0 else HypothesisStatus.CONFIRMED
    return HypothesisResult(id=hid, title=hid, origin=origin, confidence=confidence, status=status,
                            checks=[check(Verdict.INCONCLUSIVE, 1.0, required=True)])


def test_attribution_needs_confidence_and_a_margin():
    assert attribute(rank([result("a", 0.9), result("b", 0.5)])) [0] is Attribution.ATTRIBUTED
    assert attribute(rank([result("a", 0.9), result("b", 0.8)]))[0] is Attribution.AMBIGUOUS
    assert attribute(rank([result("a", 0.55), result("b", 0.1)])) == (Attribution.INCONCLUSIVE, None)
    assert attribute(rank([result("a", 0.0)])) == (Attribution.INCONCLUSIVE, None)


def test_llm_hypotheses_never_become_the_root_cause():
    attribution, root = attribute(rank([result("llm_1", 0.99, origin="llm"), result("a", 0.2)]))
    assert attribution is Attribution.INCONCLUSIVE and root is None


def test_gaps_list_unmet_prerequisites_when_nothing_is_live():
    gaps = evidence_gaps([result("a", 0.0), result("b", 0.0)], Attribution.INCONCLUSIVE)
    assert gaps == ["a: d", "b: d"]
