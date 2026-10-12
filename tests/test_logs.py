from conftest import at

from sentinelflow.collectors.logs import categorise, collect_logs, signature
from sentinelflow.models import LogRecord


def test_signature_collapses_variable_parts():
    a = signature("order 123456 failed after 250ms for user 'alice' from 10.2.3.4:8080")
    b = signature("order 999 failed after 31ms for user 'bob' from 172.16.0.9:443")
    assert a == b == "order <n> failed after <n> for user <str> from <addr>"


def test_signature_keeps_code_locations_distinct():
    assert signature("NPE in A.apply(A.java:10)") != signature("NPE in B.run(B.java:10)")


def test_categorise_maps_messages_to_failure_domains():
    assert categorise("could not acquire connection: connection pool exhausted") == "db_connection"
    assert categorise("canceling statement due to lock timeout") == "db_lock"
    assert categorise("java.lang.OutOfMemoryError: Java heap space") == "oom"
    assert categorise("call to payments-api failed: 503 Service Unavailable") == "upstream"
    assert categorise("request queue full, shedding load") == "overload"
    assert categorise("NullPointerException in DiscountEngine") == "application"


def _steady(service="checkout-api"):
    return [LogRecord(ts=at(m), service=service, level="INFO", message=f"order {m} ok") for m in range(-120, 1)]


def test_new_error_signature_and_spike_are_detected(request_factory):
    logs = _steady() + [
        LogRecord(ts=at(-10 + i * 0.2), service="checkout-api", level="ERROR", message=f"NPE in Discount.apply for order {i}")
        for i in range(40)
    ]
    evidence = collect_logs(request_factory(logs=logs))
    kinds = {e.kind: e for e in evidence}
    assert set(kinds) == {"error_spike", "new_error_signature"}
    assert kinds["new_error_signature"].attributes["count"] == 40
    assert kinds["new_error_signature"].attributes["category"] == "application"
    assert kinds["error_spike"].observed_at == at(-10)


def test_known_background_errors_are_not_reported(request_factory):
    logs = _steady() + [
        LogRecord(ts=at(m), service="checkout-api", level="ERROR", message=f"SMTP timeout sending mail {m}")
        for m in range(-120, 1, 10)
    ]
    assert collect_logs(request_factory(logs=logs)) == []


def test_surge_of_a_known_error_is_reported(request_factory):
    background = [
        LogRecord(ts=at(m), service="checkout-api", level="ERROR", message=f"SMTP timeout sending mail {m}")
        for m in range(-120, -30, 30)
    ]
    burst = [
        LogRecord(ts=at(-8 + i * 0.1), service="checkout-api", level="ERROR", message=f"SMTP timeout sending mail {i}")
        for i in range(60)
    ]
    kinds = [e.kind for e in collect_logs(request_factory(logs=_steady() + background + burst))]
    assert "error_signature_surge" in kinds and "new_error_signature" not in kinds


def test_out_of_scope_services_are_ignored(request_factory):
    logs = _steady("search-api") + [
        LogRecord(ts=at(-5 + i * 0.1), service="search-api", level="ERROR", message=f"index corrupt {i}") for i in range(30)
    ]
    assert collect_logs(request_factory(logs=logs)) == []


def test_dependency_mentions_are_extracted(request_factory):
    logs = _steady() + [
        LogRecord(ts=at(-6 + i * 0.1), service="checkout-api", level="ERROR",
                  message=f"call to payments-api failed: 503 Service Unavailable (attempt {i})")
        for i in range(20)
    ]
    new = [e for e in collect_logs(request_factory(logs=logs)) if e.kind == "new_error_signature"]
    assert new[0].attributes["mentions"] == ["payments-api"]
    assert new[0].attributes["category"] == "upstream"


def test_signature_treats_negative_and_decimal_numbers_as_numbers():
    assert signature("offset -120 drift 3.5%") == signature("offset 7 drift 0.25%")
    assert signature("deployed v2.41.0") == "deployed v2.41.0"
