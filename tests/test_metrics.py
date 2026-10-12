import random

from conftest import at

from sentinelflow.collectors.metrics import collect_metrics, linear_fit
from sentinelflow.models import MetricSeries


def series(shape, name="latency_p99_ms", service="checkout-api", base=180.0, noise=10.0, limit=None, seed=7):
    rng = random.Random(seed)
    points = [(at(m), base + rng.gauss(0, noise) + shape(m)) for m in range(-120, 1)]
    return MetricSeries(name=name, service=service, limit=limit, points=points)


def test_quiet_series_produces_no_evidence(request_factory):
    for seed in range(20):
        assert collect_metrics(request_factory(metrics=[series(lambda m: 0.0, seed=seed)])) == []


def test_step_change_is_an_anomaly_with_the_right_onset(request_factory):
    evidence = collect_metrics(request_factory(metrics=[series(lambda m: 900.0 if m >= -15 else 0.0)]))
    assert [e.kind for e in evidence] == ["metric_anomaly"]
    assert evidence[0].attributes["direction"] == "up"
    assert evidence[0].observed_at == at(-15)


def test_onset_ignores_an_earlier_noise_blip(request_factory):
    def shape(m):
        if m in (-26, -25):
            return 45.0  # two unlucky points, then back to normal
        return 900.0 if m >= -12 else 0.0

    evidence = collect_metrics(request_factory(metrics=[series(shape)]))
    assert evidence[0].observed_at == at(-12)


def test_onset_before_the_lookback_window_is_still_found(request_factory):
    evidence = collect_metrics(request_factory(metrics=[series(lambda m: 900.0 if m >= -40 else 0.0)]))
    assert evidence[0].observed_at == at(-40)


def test_drop_is_reported_as_downward_anomaly(request_factory):
    evidence = collect_metrics(request_factory(metrics=[series(lambda m: -150.0 if m >= -10 else 0.0)]))
    assert evidence[0].attributes["direction"] == "down"


def test_linear_growth_is_a_trend_but_a_step_is_not(request_factory):
    leak = series(lambda m: 9.0 * (m + 120), name="memory_mb", base=900, noise=14, limit=2048)
    step = series(lambda m: 600.0 if m >= -20 else 0.0, name="memory_mb", base=900, noise=14, limit=2048)
    leak_kinds = {e.kind for e in collect_metrics(request_factory(metrics=[leak]))}
    step_kinds = {e.kind for e in collect_metrics(request_factory(metrics=[step]))}
    assert "metric_trend" in leak_kinds and "metric_saturation" in leak_kinds
    assert "metric_trend" not in step_kinds and "metric_anomaly" in step_kinds


def test_linear_fit_recovers_slope():
    points = [(at(m), 3.0 * m + 5) for m in range(0, 60)]
    slope, r2 = linear_fit(points)
    assert abs(slope - 3.0) < 1e-9 and abs(r2 - 1.0) < 1e-9


def test_too_little_history_is_skipped(request_factory):
    short = MetricSeries(name="latency_p99_ms", service="checkout-api", points=[(at(m), 5000.0) for m in range(-3, 1)])
    assert collect_metrics(request_factory(metrics=[short])) == []
