import json

from sentinelflow.hypotheses.llm import LLM_CONFIDENCE_CAP, OpenAICompatibleClient, client_from_env
from sentinelflow.models import HypothesisStatus
from sentinelflow.pipeline import triage
from sentinelflow.scenarios import generate


class FakeLLM:
    def __init__(self, reply):
        self.reply, self.prompts = reply, []

    def complete(self, system, user):
        self.prompts.append((system, user))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def proposals(*items):
    return json.dumps({"hypotheses": list(items)})


def llm_results(report):
    return [h for h in report.hypotheses if h.origin == "llm"]


def test_grounded_proposal_is_kept_but_capped_below_attribution():
    request = generate("bad_deploy", 0)
    ids = [e.id for e in triage(request).evidence]
    logs, deploys = next(i for i in ids if i.startswith("log")), next(i for i in ids if i.startswith("dep"))
    llm = FakeLLM(proposals({"title": "Feature flag rollout", "rationale": "r", "evidence_ids": [logs, deploys],
                             "remediation": ["Disable the flag"]}))
    report = triage(request, llm=llm)
    [result] = llm_results(report)
    assert result.status is HypothesisStatus.PLAUSIBLE
    assert 0 < result.confidence <= LLM_CONFIDENCE_CAP
    assert report.root_cause.id == "bad_deploy" and report.root_cause.origin == "catalog"
    assert f"[{logs}]" in llm.prompts[0][1]


def test_proposal_citing_invented_evidence_is_rejected():
    request = generate("bad_deploy", 0)
    ids = [e.id for e in triage(request).evidence][:2]
    llm = FakeLLM(proposals({"title": "DNS outage", "evidence_ids": [*ids, "dns-99"], "remediation": ["x"]}))
    [result] = llm_results(triage(request, llm=llm))
    assert result.status is HypothesisStatus.REJECTED and result.confidence == 0 and result.remediation == []


def test_proposal_without_enough_real_citations_is_dropped():
    llm = FakeLLM(proposals({"title": "Cosmic rays", "evidence_ids": ["nope-1", "nope-2"]},
                            {"title": "No citations at all"}))
    assert llm_results(triage(generate("bad_deploy", 0), llm=llm)) == []


def test_malformed_output_and_client_errors_do_not_fail_triage():
    for reply in ["I think it is DNS.", "{not json", '{"hypotheses": "none"}', RuntimeError("timeout")]:
        report = triage(generate("memory_leak", 0), llm=FakeLLM(reply))
        assert llm_results(report) == [] and report.root_cause.id == "memory_leak"


def test_llm_is_not_called_when_there_is_no_evidence(request_factory):
    llm = FakeLLM(proposals())
    triage(request_factory(), llm=llm)
    assert llm.prompts == []


def test_client_is_disabled_without_an_api_key(monkeypatch):
    monkeypatch.delenv("SENTINELFLOW_LLM_API_KEY", raising=False)
    assert client_from_env() is None
    monkeypatch.setenv("SENTINELFLOW_LLM_API_KEY", "k")
    monkeypatch.setenv("SENTINELFLOW_LLM_BASE_URL", "https://api.groq.com/openai/v1/")
    client = client_from_env()
    assert isinstance(client, OpenAICompatibleClient) and client.base_url == "https://api.groq.com/openai/v1"
