"""Error spikes and new or surging error messages from application logs."""

from __future__ import annotations

import re
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

from sentinelflow.models import Evidence, LogRecord, TriageRequest

ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL"}

_NORMALISERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<addr>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"'[^']*'|\"[^\"]*\""), "<str>"),
    (re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?\s?(?:ms|s|mb|gb|kb|%)?(?!\w)", re.I), "<n>"),
]

# Keyword families that tie an error template to a failure domain. Hypothesis
# checks use the category, never the raw text.
CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "db_connection": re.compile(
        r"too many (?:clients|connections)|connection pool|pool exhausted|"
        r"timeout (?:waiting for|acquiring) (?:a )?connection|remaining connection slots",
        re.I,
    ),
    "db_lock": re.compile(
        r"deadlock detected|lock wait timeout|could not obtain lock|lock timeout|"
        r"canceling statement due to (?:lock|statement) timeout",
        re.I,
    ),
    "oom": re.compile(r"out ?of ?memory|oomkilled|memoryerror|java heap space|cannot allocate memory", re.I),
    "upstream": re.compile(
        r"upstream|connection refused|connection reset|bad gateway|service unavailable|"
        r"circuit breaker|\b50[234]\b|timed out calling|call to .* failed",
        re.I,
    ),
    "overload": re.compile(r"load shed|request queue full|rate limit|too many requests|\b429\b|thread pool exhausted", re.I),
}


def signature(message: str) -> str:
    """Collapse a log message into its template."""
    text = message
    for pattern, placeholder in _NORMALISERS:
        text = pattern.sub(placeholder, text)
    return re.sub(r"\s+", " ", text).strip()


def categorise(message: str) -> str:
    for category, pattern in CATEGORY_PATTERNS.items():
        if pattern.search(message):
            return category
    return "application"


def _per_minute(records: list[LogRecord], start: datetime, end: datetime) -> list[int]:
    minutes = max(1, int((end - start).total_seconds() // 60))
    buckets = [0] * minutes
    for record in records:
        index = int((record.ts - start).total_seconds() // 60)
        if 0 <= index < minutes:
            buckets[index] += 1
    return buckets


def _onset(errors: list[LogRecord], start: datetime, end: datetime, threshold: float) -> datetime:
    """First minute where the error count exceeds ``threshold`` and stays there."""
    buckets = _per_minute(errors, start, end)
    for index, count in enumerate(buckets):
        following = buckets[index + 1] if index + 1 < len(buckets) else count
        if count > threshold and following > threshold:
            return start + timedelta(minutes=index)
    return min((r.ts for r in errors), default=start)


def collect_logs(request: TriageRequest) -> list[Evidence]:
    scope = request.in_scope()
    dependencies = request.dependencies()
    window_start, detected_at = request.window_start, request.detected_at
    by_service: dict[str, list[LogRecord]] = defaultdict(list)
    for record in request.logs:
        if record.service in scope and record.ts <= detected_at:
            by_service[record.service].append(record)

    evidence: list[Evidence] = []
    for service, records in sorted(by_service.items()):
        errors = [r for r in records if r.level.upper() in ERROR_LEVELS]
        baseline = [r for r in errors if r.ts < window_start]
        window = [r for r in errors if r.ts >= window_start]
        if not window:
            continue

        first_ts = min(r.ts for r in records)
        baseline_minutes = max(1.0, (window_start - first_ts).total_seconds() / 60)
        window_minutes = float(request.lookback_minutes)
        baseline_buckets = _per_minute(baseline, first_ts, window_start) if first_ts < window_start else [0]
        base_rate = len(baseline) / baseline_minutes
        base_std = statistics.pstdev(baseline_buckets) if len(baseline_buckets) > 1 else 0.0
        threshold = max(2.0, base_rate + 3 * base_std)
        window_rate = len(window) / window_minutes
        peak = max(_per_minute(window, window_start, detected_at))

        if len(window) >= 5 and peak > threshold and window_rate >= max(3 * base_rate, 0.2):
            onset = _onset(window, window_start, detected_at, threshold)
            evidence.append(
                Evidence(
                    id="",
                    source="logs",
                    kind="error_spike",
                    service=service,
                    observed_at=onset,
                    summary=(
                        f"{service} error volume rose from {base_rate:.2f}/min (baseline) to "
                        f"{window_rate:.2f}/min, peaking at {peak}/min"
                    ),
                    severity=min(1.0, 0.4 + 0.1 * (peak / threshold)),
                    attributes={
                        "onset": onset.isoformat(),
                        "baseline_per_min": round(base_rate, 3),
                        "window_per_min": round(window_rate, 3),
                        "peak_per_min": peak,
                        "errors_in_window": len(window),
                    },
                )
            )

        baseline_counts: dict[str, int] = defaultdict(int)
        for record in baseline:
            baseline_counts[signature(record.message)] += 1
        grouped: dict[str, list[LogRecord]] = defaultdict(list)
        for record in window:
            grouped[signature(record.message)].append(record)

        for sig, group in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            if len(group) < 3:
                continue
            before = baseline_counts.get(sig, 0)
            before_rate = before / baseline_minutes
            now_rate = len(group) / window_minutes
            if before == 0:
                kind = "new_error_signature"
            elif now_rate >= 5 * before_rate:
                kind = "error_signature_surge"
            else:
                continue
            first_seen = min(r.ts for r in group)
            example = group[0].message
            mentions = [dep for dep in dependencies if dep.lower() in example.lower()]
            label = "New" if kind == "new_error_signature" else "Surging"
            evidence.append(
                Evidence(
                    id="",
                    source="logs",
                    kind=kind,
                    service=service,
                    observed_at=first_seen,
                    summary=f"{label} error in {service} ({len(group)}x in window): {example[:140]}",
                    severity=min(1.0, 0.3 + len(group) / 50),
                    attributes={
                        "signature": sig,
                        "category": categorise(example),
                        "count": len(group),
                        "baseline_count": before,
                        "first_seen": first_seen.isoformat(),
                        "mentions": mentions,
                        "example": example,
                    },
                )
            )
    return evidence
