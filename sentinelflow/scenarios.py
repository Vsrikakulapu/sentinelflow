"""Synthetic incident generator.

Produces realistic, seeded ``TriageRequest`` bundles for six failure modes
plus two negative cases (a quiet period, and an unexplained latency rise).
Used by the test-suite, the evaluation harness (``python -m sentinelflow eval``)
and to create the sample bundles under ``scenarios/``.

Each scenario varies with the seed: onset time, magnitude, noise, and
*confounders* - unrelated deploys, old deploys to the affected service - so
that timing and scoping logic is exercised rather than memorised.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from sentinelflow.models import (
    BlockedQuery,
    DbSnapshot,
    DeployRecord,
    LogRecord,
    LongRunningQuery,
    MetricSeries,
    TriageRequest,
)

SERVICE = "checkout-api"
DEPENDENCIES = ["payments-api", "inventory-api"]
DATABASE = "orders-db"
DETECTED_AT = datetime(2026, 3, 14, 14, 0, tzinfo=timezone.utc)
HISTORY_MINUTES = 120
LOOKBACK_MINUTES = 30

POSITIVE = [
    "bad_deploy",
    "db_connection_exhaustion",
    "db_lock_contention",
    "memory_leak",
    "upstream_dependency_failure",
    "traffic_overload",
]
NEGATIVE = ["quiet", "unexplained_latency"]

Shape = Callable[[int], float]


def _at(minute: float) -> datetime:
    return DETECTED_AT + timedelta(minutes=minute)


def _ramp(minute: int, start: float, length: float) -> float:
    """0 before ``start``, rising linearly to 1 over ``length`` minutes."""
    return max(0.0, min(1.0, (minute - start) / max(length, 1e-9)))


class _Builder:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.onset = self.rng.randint(-24, -10)
        self.magnitude = self.rng.uniform(0.7, 1.4)
        self.metrics: dict[tuple[str, str], MetricSeries] = {}
        self.logs: list[LogRecord] = []
        self.snapshots: list[DbSnapshot] = []
        self.deploys: list[DeployRecord] = []
        self._baseline()

    # -- raw signal helpers -------------------------------------------------

    def series(self, name: str, service: str, base: float, noise: float, shape: Shape | None = None,
               limit: float | None = None) -> None:
        points = []
        for minute in range(-HISTORY_MINUTES, 1):
            value = base + self.rng.gauss(0, noise) + (shape(minute) if shape else 0.0)
            if limit is not None:
                value = min(value, limit)
            points.append((_at(minute), round(max(0.0, value), 4)))
        self.metrics[(service, name)] = MetricSeries(name=name, service=service, limit=limit, points=points)

    def log(self, minute: float, service: str, level: str, message: str) -> None:
        self.logs.append(LogRecord(ts=_at(minute), service=service, level=level, message=message))

    def log_burst(self, start: int, per_minute: float, service: str, level: str, template: Callable[[], str]) -> None:
        for minute in range(start, 1):
            count = int(per_minute) + (1 if self.rng.random() < per_minute % 1 else 0)
            for _ in range(count):
                self.log(minute + self.rng.random() * 0.98, service, level, template())

    def deploy(self, minute: float, service: str, version: str, kind: str = "code", summary: str = "") -> None:
        self.deploys.append(DeployRecord(id=f"d-{len(self.deploys) + 1}", service=service, version=version,
                                         deployed_at=_at(minute), kind=kind, summary=summary))

    def snapshot(self, minute: int, **overrides) -> None:
        values = dict(max_connections=60, active=self.rng.randint(14, 20), idle=self.rng.randint(8, 12),
                      idle_in_transaction=self.rng.randint(0, 2), deadlocks_total=3)
        values.update(overrides)
        self.snapshots.append(DbSnapshot(captured_at=_at(minute), database=DATABASE, **values))

    # -- normal behaviour ---------------------------------------------------

    def _baseline(self) -> None:
        order = lambda: self.rng.randint(100000, 999999)  # noqa: E731
        for minute in range(-HISTORY_MINUTES, 1):
            for _ in range(2):
                self.log(minute + self.rng.random(), SERVICE, "INFO",
                         f"order {order()} placed in {self.rng.randint(90, 260)}ms")
            for dep in DEPENDENCIES:
                self.log(minute + self.rng.random(), dep, "INFO", f"handled request {order()} in {self.rng.randint(20, 90)}ms")
            if self.rng.random() < 0.06:
                self.log(minute + self.rng.random(), SERVICE, "ERROR",
                         f"failed to send confirmation email for order {order()}: SMTP timeout after {self.rng.randint(5, 9)}s")
        for dep in DEPENDENCIES:
            self.series("latency_p99_ms", dep, 95, 6)
            self.series("error_rate", dep, 0.003, 0.0006)

    def quiet_metrics(self, skip: set[str] = frozenset()) -> None:
        defaults = {
            "latency_p99_ms": (180, 11, None), "error_rate": (0.004, 0.0008, None),
            "request_rate": (240, 12, None), "cpu_util": (0.42, 0.025, 1.0),
            "memory_mb": (900, 14, 2048), "db_connections_active": (22, 2.2, 50),
            "container_restarts": (0, 0, None),
        }
        for name, (base, noise, limit) in defaults.items():
            if name not in skip and (SERVICE, name) not in self.metrics:
                self.series(name, SERVICE, base, noise, limit=limit)

    def quiet_snapshots(self, until: int = 0) -> None:
        for minute in range(-HISTORY_MINUTES, until + 1, 5):
            self.snapshot(minute)

    def confounders(self) -> None:
        """Deploys that must *not* be blamed: out of scope, or long before onset."""
        if self.rng.random() < 0.6:
            self.deploy(self.onset - self.rng.randint(1, 8), "search-api", "v9.3.1", summary="Reindex tuning")
        if self.rng.random() < 0.5:
            self.deploy(self.onset - self.rng.randint(150, 260), SERVICE, "v2.40.3", summary="Copy changes")
        if self.rng.random() < 0.4:
            self.deploy(self.onset - self.rng.randint(120, 300), "inventory-api", "v5.12.0", summary="Dependency bumps")

    def symptoms(self, latency: float, errors: float, start: int | None = None, length: float = 3) -> None:
        start = self.onset if start is None else start
        m = self.magnitude
        self.series("latency_p99_ms", SERVICE, 180, 11, lambda t: latency * m * _ramp(t, start, length))
        self.series("error_rate", SERVICE, 0.004, 0.0008, lambda t: errors * m * _ramp(t, start, length))

    def build(self) -> TriageRequest:
        self.quiet_metrics()
        return TriageRequest(
            service=SERVICE,
            detected_at=DETECTED_AT,
            lookback_minutes=LOOKBACK_MINUTES,
            topology={SERVICE: list(DEPENDENCIES), "payments-api": [], "inventory-api": []},
            logs=sorted(self.logs, key=lambda r: r.ts),
            metrics=list(self.metrics.values()),
            db_snapshots=self.snapshots,
            deploys=self.deploys,
        )


# --------------------------------------------------------------------- scenarios


def _bad_deploy(b: _Builder) -> None:
    b.confounders()
    b.deploy(b.onset - b.rng.randint(1, 4), SERVICE, "v2.41.0", summary="Refactor discount engine")
    b.symptoms(latency=90, errors=0.07)
    b.log_burst(b.onset, 5 * b.magnitude, SERVICE, "ERROR",
                lambda: f"NullPointerException in DiscountEngine.apply(DiscountEngine.java:118) for order {b.rng.randint(100000, 999999)}")
    b.quiet_snapshots()


def _db_connection_exhaustion(b: _Builder) -> None:
    b.confounders()
    fill = b.onset - 6
    b.series("db_connections_active", SERVICE, 22, 2.2, lambda t: 30 * _ramp(t, fill, 6), limit=50)
    b.symptoms(latency=2200, errors=0.06)
    b.log_burst(b.onset, 4 * b.magnitude, SERVICE, "ERROR",
                lambda: f"could not acquire connection: connection pool exhausted (active=50, idle=0, waiting={b.rng.randint(4, 40)})")
    b.log_burst(b.onset + 2, 0.5, SERVICE, "ERROR",
                lambda: "FATAL: remaining connection slots are reserved for non-replication superuser connections")
    for minute in range(-HISTORY_MINUTES, 1, 5):
        if minute < fill:
            b.snapshot(minute)
        else:
            # Server-side view of the same leak the client pool metric shows.
            held = round(34 * _ramp(minute, fill, 6)) + b.rng.randint(0, 2)
            b.snapshot(minute, active=b.rng.randint(16, 19), idle=b.rng.randint(0, 2), idle_in_transaction=held,
                       long_running_queries=[LongRunningQuery(pid=3100 + i, duration_s=60.0 * (minute - fill) + 45 + 30 * i,
                                                              state="idle in transaction",
                                                              query="UPDATE orders SET status = $1 WHERE id = $2")
                                             for i in range(3)])


def _db_lock_contention(b: _Builder) -> None:
    b.confounders()
    started = b.onset - 2
    b.deploy(started, SERVICE, "migration-0147", kind="migration",
             summary="ALTER TABLE orders ADD COLUMN fulfilment_region")
    b.symptoms(latency=3000, errors=0.04, length=2)
    b.series("db_connections_active", SERVICE, 22, 2.2, lambda t: 14 * _ramp(t, started, 4), limit=50)
    b.series("cpu_util", SERVICE, 0.42, 0.025, lambda t: -0.08 * _ramp(t, b.onset, 3), limit=1.0)
    b.log_burst(b.onset + 1, 3 * b.magnitude, SERVICE, "ERROR",
                lambda: f"canceling statement due to lock timeout while updating orders (order {b.rng.randint(100000, 999999)})")
    ddl = "ALTER TABLE orders ADD COLUMN fulfilment_region text NOT NULL DEFAULT 'us'"
    for minute in range(-HISTORY_MINUTES, 1, 5):
        if minute < started:
            b.snapshot(minute)
        else:
            waited = 60.0 * (minute - started) + 20
            blocked = [BlockedQuery(blocked_pid=5000 + i, blocking_pid=4242, blocked_duration_s=max(1.0, waited - 7 * i),
                                    lock_type="relation", relation="orders", blocking_query=ddl)
                       for i in range(b.rng.randint(9, 16))]
            b.snapshot(minute, active=b.rng.randint(30, 36), idle=b.rng.randint(3, 6), waiting_on_lock=len(blocked),
                       blocked_queries=blocked,
                       long_running_queries=[LongRunningQuery(pid=4242, duration_s=waited + 5, query=ddl)])


def _memory_leak(b: _Builder) -> None:
    b.confounders()
    if b.rng.random() < 0.5:
        b.deploy(b.onset - b.rng.randint(200, 300), SERVICE, "v2.40.9", summary="Add in-memory product cache")
    growth = 1080 / HISTORY_MINUTES
    b.series("memory_mb", SERVICE, 900, 14, lambda t: growth * (t + HISTORY_MINUTES), limit=2048)
    b.symptoms(latency=420, errors=0.03, length=6)
    kills = b.onset + 3
    b.series("container_restarts", SERVICE, 0, 0, lambda t: float(max(0, (t - kills) // 4 + 1)) if t >= kills else 0.0)
    b.log_burst(kills, 1.5 * b.magnitude, SERVICE, "ERROR",
                lambda: f"java.lang.OutOfMemoryError: Java heap space (heap used {b.rng.randint(1900, 2040)}MB)")
    b.quiet_snapshots()


def _upstream_dependency_failure(b: _Builder) -> None:
    b.confounders()
    dep, dep_onset = "payments-api", b.onset - 2
    if b.rng.random() < 0.5:
        b.deploy(dep_onset - b.rng.randint(2, 6), dep, "v7.8.0", summary="Switch bank gateway client")
    b.series("error_rate", dep, 0.003, 0.0006, lambda t: 0.30 * b.magnitude * _ramp(t, dep_onset, 2))
    b.series("latency_p99_ms", dep, 95, 6, lambda t: 900 * b.magnitude * _ramp(t, dep_onset, 2))
    b.log_burst(dep_onset, 4 * b.magnitude, dep, "ERROR",
                lambda: f"bank gateway returned 503 for charge {b.rng.randint(1000, 9999)}")
    b.symptoms(latency=700, errors=0.11)
    b.log_burst(b.onset, 4 * b.magnitude, SERVICE, "ERROR",
                lambda: f"call to payments-api failed: 503 Service Unavailable (attempt {b.rng.randint(1, 3)}/3)")
    b.quiet_snapshots()


def _traffic_overload(b: _Builder) -> None:
    b.confounders()
    surge = b.onset - 3
    b.series("request_rate", SERVICE, 240, 12, lambda t: 620 * b.magnitude * _ramp(t, surge, 8))
    b.series("cpu_util", SERVICE, 0.42, 0.025, lambda t: 0.56 * _ramp(t, surge, 8), limit=1.0)
    b.series("db_connections_active", SERVICE, 22, 2.2, lambda t: 13 * _ramp(t, surge, 8), limit=50)
    b.symptoms(latency=1300, errors=0.05, length=6)
    b.log_burst(b.onset, 3 * b.magnitude, SERVICE, "ERROR",
                lambda: f"request queue full, shedding load (queued={b.rng.randint(400, 600)})")
    for minute in range(-HISTORY_MINUTES, 1, 5):
        b.snapshot(minute, **({"active": b.rng.randint(30, 34)} if minute >= b.onset else {}))


def _quiet(b: _Builder) -> None:
    b.confounders()
    b.quiet_snapshots()


def _unexplained_latency(b: _Builder) -> None:
    """Latency rises with no corroborating signal anywhere: the right answer is 'unknown'."""
    b.confounders()
    b.series("latency_p99_ms", SERVICE, 180, 11, lambda t: 260 * b.magnitude * _ramp(t, b.onset, 4))
    b.quiet_snapshots()


_SCENARIOS: dict[str, Callable[[_Builder], None]] = {
    "bad_deploy": _bad_deploy,
    "db_connection_exhaustion": _db_connection_exhaustion,
    "db_lock_contention": _db_lock_contention,
    "memory_leak": _memory_leak,
    "upstream_dependency_failure": _upstream_dependency_failure,
    "traffic_overload": _traffic_overload,
    "quiet": _quiet,
    "unexplained_latency": _unexplained_latency,
}


def generate(kind: str, seed: int = 0) -> TriageRequest:
    """Build one incident bundle. ``kind`` is a key of ``POSITIVE`` or ``NEGATIVE``."""
    if kind not in _SCENARIOS:
        raise ValueError(f"unknown scenario {kind!r}; choose from {sorted(_SCENARIOS)}")
    builder = _Builder(seed * 1009 + sorted(_SCENARIOS).index(kind))
    _SCENARIOS[kind](builder)
    return builder.build()


def expected_root_cause(kind: str) -> str | None:
    return kind if kind in POSITIVE else None
