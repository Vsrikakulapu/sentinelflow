"""Service-metrics collector.

For every in-scope time series this emits up to three kinds of evidence:

* ``metric_anomaly``    - the incident window deviates from the reference period
  (robust z-score on median / MAD, so a single outlier cannot trigger it)
* ``metric_trend``      - sustained, near-linear growth across the whole series
  (what a leak looks like, as opposed to a step change after a deploy)
* ``metric_saturation`` - the series reached its declared limit

Each anomaly carries an *onset* timestamp. Onsets are what make temporal
verification possible: a cause has to start before its effect.
"""

from __future__ import annotations

import statistics
from datetime import datetime

from sentinelflow.models import Evidence, MetricSeries, TriageRequest

Z_THRESHOLD = 4.0
ONSET_SIGMA = 3.0
TREND_R2 = 0.85
TREND_MIN_GROWTH = 0.30
SATURATION_RATIO = 0.90


def robust_sigma(values: list[float]) -> float:
    """Scale estimate that tolerates outliers and near-constant series."""
    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values)
    return max(1.4826 * mad, 0.05 * abs(median), 1e-9)


def find_onset(
    points: list[tuple[datetime, float]], centre: float, sigma: float, direction: str
) -> datetime | None:
    """Start of the excursion that contains the peak.

    Walks backwards from the most extreme point while values stay beyond
    3 sigma (tolerating a single in-range point), so an isolated noise blip
    earlier in the series is never mistaken for the start of the incident.
    """
    if not points:
        return None
    sign = 1.0 if direction == "up" else -1.0
    deviation = [sign * (value - centre) for _, value in points]
    beyond = [d > ONSET_SIGMA * sigma for d in deviation]
    index = max(range(len(points)), key=lambda i: deviation[i])
    if not beyond[index]:
        return None
    while index > 0 and (beyond[index - 1] or (index > 1 and beyond[index - 2])):
        index -= 1
    return points[index][0]


def linear_fit(points: list[tuple[datetime, float]]) -> tuple[float, float]:
    """Least-squares slope (per minute) and R^2 of value against time."""
    origin = points[0][0]
    xs = [(ts - origin).total_seconds() / 60 for ts, _ in points]
    ys = [value for _, value in points]
    mean_x, mean_y = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mean_x) ** 2 for x in xs)
    syy = sum((y - mean_y) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return 0.0, 0.0
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    return sxy / sxx, (sxy * sxy) / (sxx * syy)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))]


def analyse_series(series: MetricSeries, request: TriageRequest) -> list[Evidence]:
    points = [(ts, value) for ts, value in series.points if ts <= request.detected_at]
    before = [p for p in points if p[0] < request.window_start]
    window = [p for p in points if p[0] >= request.window_start]
    if len(before) < 6 or len(window) < 3:
        return []

    # The oldest half of the pre-incident data is the reference: a problem that
    # started shortly before the lookback window must not poison its own baseline.
    reference = [value for _, value in before[: max(4, len(before) // 2)]]
    centre = statistics.median(reference)
    sigma = robust_sigma(reference)
    after_reference = points[len(reference):]
    window_values = [value for _, value in window]
    label = f"{series.service}.{series.name}"
    evidence: list[Evidence] = []

    z_up = (_percentile(window_values, 0.9) - centre) / sigma
    z_down = (centre - _percentile(window_values, 0.1)) / sigma
    direction = "up" if z_up >= z_down else "down"
    z = max(z_up, z_down)
    if z >= Z_THRESHOLD:
        onset = find_onset(after_reference, centre, sigma, direction) or window[0][0]
        peak = max(window_values) if direction == "up" else min(window_values)
        evidence.append(
            Evidence(
                id="",
                source="metrics",
                kind="metric_anomaly",
                service=series.service,
                observed_at=onset,
                summary=(
                    f"{label} went {direction} from ~{centre:.4g} to {peak:.4g} "
                    f"({z:.1f} robust sigma), starting {onset:%H:%M} UTC"
                ),
                severity=min(1.0, 0.3 + z / 40),
                attributes={
                    "metric": series.name,
                    "direction": direction,
                    "baseline": round(centre, 4),
                    "peak": round(peak, 4),
                    "z": round(z, 2),
                    "onset": onset.isoformat(),
                },
            )
        )

    slope, r2 = linear_fit(points)
    start_level = statistics.median(v for _, v in points[:5])
    end_level = statistics.median(v for _, v in points[-5:])
    growth = (end_level - start_level) / abs(start_level) if start_level else 0.0
    if slope > 0 and r2 >= TREND_R2 and growth >= TREND_MIN_GROWTH:
        attributes = {
            "metric": series.name,
            "slope_per_min": round(slope, 4),
            "r2": round(r2, 3),
            "growth": round(growth, 3),
            "started": points[0][0].isoformat(),
        }
        if series.limit and slope > 0 and end_level < series.limit:
            attributes["minutes_to_limit"] = round((series.limit - end_level) / slope, 1)
        evidence.append(
            Evidence(
                id="",
                source="metrics",
                kind="metric_trend",
                service=series.service,
                observed_at=points[0][0],
                summary=(
                    f"{label} grew steadily by {growth:.0%} over "
                    f"{(points[-1][0] - points[0][0]).total_seconds() / 60:.0f} min "
                    f"(linear fit R^2={r2:.2f})"
                ),
                severity=min(1.0, 0.4 + growth / 2),
                attributes=attributes,
            )
        )

    if series.limit and max(window_values) >= SATURATION_RATIO * series.limit:
        hit_at = next(ts for ts, value in window if value >= SATURATION_RATIO * series.limit)
        evidence.append(
            Evidence(
                id="",
                source="metrics",
                kind="metric_saturation",
                service=series.service,
                observed_at=hit_at,
                summary=(
                    f"{label} reached {max(window_values):.4g} of limit {series.limit:.4g} "
                    f"({max(window_values) / series.limit:.0%})"
                ),
                severity=min(1.0, max(window_values) / series.limit),
                attributes={
                    "metric": series.name,
                    "limit": series.limit,
                    "peak": round(max(window_values), 4),
                    "ratio": round(max(window_values) / series.limit, 3),
                },
            )
        )
    return evidence


def collect_metrics(request: TriageRequest) -> list[Evidence]:
    scope = request.in_scope()
    evidence: list[Evidence] = []
    for series in request.metrics:
        if series.service in scope:
            evidence.extend(analyse_series(series, request))
    return evidence
