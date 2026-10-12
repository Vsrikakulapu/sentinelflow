"""Database-health collector.

Works from ``DbSnapshot`` objects, which come from one of two places:

* ``PostgresHealthProbe`` - queries a live PostgreSQL instance
  (``pg_stat_activity``, ``pg_blocking_pids``, ``pg_stat_database``)
* snapshots supplied with the triage request (replayed incidents, tests)

Both paths feed the same analysis, so the logic that is unit-tested is the
logic that runs against a real database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sentinelflow.models import BlockedQuery, DbSnapshot, Evidence, LongRunningQuery, TriageRequest

SATURATION_RATIO = 0.85
LONG_QUERY_SECONDS = 60.0
BLOCKED_SECONDS = 30.0
REPLICATION_LAG_SECONDS = 30.0

SQL_MAX_CONNECTIONS = "SELECT current_setting('max_connections')::int"

SQL_CONNECTION_STATES = """
SELECT COALESCE(state, 'unknown') AS state, count(*)::int AS sessions
FROM pg_stat_activity
WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()
GROUP BY 1
"""

SQL_LOCK_WAITERS = """
SELECT count(*)::int
FROM pg_stat_activity
WHERE backend_type = 'client backend' AND wait_event_type = 'Lock'
"""

SQL_LONG_RUNNING = """
SELECT pid,
       EXTRACT(EPOCH FROM (now() - query_start))::float8 AS duration_s,
       state,
       left(query, 200) AS query,
       wait_event_type
FROM pg_stat_activity
WHERE backend_type = 'client backend'
  AND pid <> pg_backend_pid()
  AND state IN ('active', 'idle in transaction')
  AND now() - query_start > make_interval(secs => %(min_seconds)s)
ORDER BY duration_s DESC
LIMIT 20
"""

SQL_BLOCKED = """
SELECT blocked.pid AS blocked_pid,
       blocking.pid AS blocking_pid,
       EXTRACT(EPOCH FROM (now() - blocked.query_start))::float8 AS blocked_duration_s,
       COALESCE(waiting.locktype, 'unknown') AS lock_type,
       COALESCE(waiting.relation::regclass::text, '') AS relation,
       left(blocking.query, 200) AS blocking_query
FROM pg_stat_activity AS blocked
JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS blocker(pid) ON true
JOIN pg_stat_activity AS blocking ON blocking.pid = blocker.pid
LEFT JOIN LATERAL (
    SELECT locktype, relation FROM pg_locks
    WHERE pid = blocked.pid AND NOT granted
    LIMIT 1
) AS waiting ON true
ORDER BY blocked_duration_s DESC
LIMIT 50
"""

SQL_DEADLOCKS = "SELECT COALESCE(sum(deadlocks), 0)::bigint FROM pg_stat_database"

SQL_REPLICATION_LAG = """
SELECT CASE WHEN pg_is_in_recovery()
            THEN EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::float8
       END
"""


class PostgresHealthProbe:
    """Takes a ``DbSnapshot`` of a live PostgreSQL instance.

    ``connection`` is any DB-API connection whose driver uses ``%(name)s``
    parameters (psycopg 3 in production). It is injected so the probe can be
    exercised without a database driver installed.
    """

    def __init__(self, connection: Any, database: str = "postgres") -> None:
        self._connection = connection
        self._database = database

    def _rows(self, sql: str, params: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        with self._connection.cursor() as cursor:
            cursor.execute(sql, params)
            return list(cursor.fetchall())

    def snapshot(self, long_query_seconds: float = 5.0) -> DbSnapshot:
        states = {state: sessions for state, sessions in self._rows(SQL_CONNECTION_STATES)}
        return DbSnapshot(
            captured_at=datetime.now(timezone.utc),
            database=self._database,
            max_connections=self._rows(SQL_MAX_CONNECTIONS)[0][0],
            active=states.get("active", 0),
            idle=states.get("idle", 0),
            idle_in_transaction=states.get("idle in transaction", 0)
            + states.get("idle in transaction (aborted)", 0),
            waiting_on_lock=self._rows(SQL_LOCK_WAITERS)[0][0],
            long_running_queries=[
                LongRunningQuery(
                    pid=pid, duration_s=duration, state=state, query=query or "", wait_event_type=wait
                )
                for pid, duration, state, query, wait in self._rows(
                    SQL_LONG_RUNNING, {"min_seconds": long_query_seconds}
                )
            ],
            blocked_queries=[
                BlockedQuery(
                    blocked_pid=blocked,
                    blocking_pid=blocking,
                    blocked_duration_s=duration,
                    lock_type=lock_type,
                    relation=relation,
                    blocking_query=query or "",
                )
                for blocked, blocking, duration, lock_type, relation, query in self._rows(SQL_BLOCKED)
            ],
            deadlocks_total=int(self._rows(SQL_DEADLOCKS)[0][0]),
            replication_lag_s=self._rows(SQL_REPLICATION_LAG)[0][0],
        )


def _make(kind: str, snapshot: DbSnapshot, summary: str, severity: float, **attributes: Any) -> Evidence:
    return Evidence(
        id="",
        source="database",
        kind=kind,
        service=snapshot.database,
        observed_at=snapshot.captured_at,
        summary=summary,
        severity=max(0.0, min(1.0, severity)),
        attributes=attributes,
    )


def analyse_snapshots(snapshots: list[DbSnapshot], request: TriageRequest) -> list[Evidence]:
    """Report each unhealthy condition once: when it first appeared, at its worst."""
    ordered = sorted(snapshots, key=lambda s: s.captured_at)
    window = [s for s in ordered if request.window_start <= s.captured_at <= request.detected_at]
    if not window:
        return []
    before = [s for s in ordered if s.captured_at < request.window_start]
    evidence: list[Evidence] = []

    saturated = [s for s in window if s.connections_used >= SATURATION_RATIO * s.max_connections]
    if saturated:
        worst = max(saturated, key=lambda s: s.connections_used / s.max_connections)
        first = saturated[0]
        # Snapshots are periodic: the pool actually filled somewhere between the
        # last healthy snapshot and the first saturated one.
        healthy = [s for s in ordered if s.captured_at < first.captured_at
                   and s.connections_used < SATURATION_RATIO * s.max_connections]
        evidence.append(
            _make(
                "connection_saturation",
                first,
                (
                    f"{worst.database} at {worst.connections_used}/{worst.max_connections} connections "
                    f"({worst.connections_used / worst.max_connections:.0%}); "
                    f"{worst.idle_in_transaction} idle in transaction"
                ),
                worst.connections_used / worst.max_connections,
                used=worst.connections_used,
                max_connections=worst.max_connections,
                ratio=round(worst.connections_used / worst.max_connections, 3),
                idle_in_transaction=worst.idle_in_transaction,
                first_seen=first.captured_at.isoformat(),
                healthy_until=healthy[-1].captured_at.isoformat() if healthy else None,
            )
        )

    leaking = [s for s in window if s.idle_in_transaction >= max(5, 0.2 * s.max_connections)]
    if leaking:
        worst = max(leaking, key=lambda s: s.idle_in_transaction)
        evidence.append(
            _make(
                "idle_in_transaction",
                leaking[0],
                f"{worst.idle_in_transaction} sessions idle in transaction on {worst.database} "
                "(connections held without doing work)",
                0.6,
                sessions=worst.idle_in_transaction,
                first_seen=leaking[0].captured_at.isoformat(),
            )
        )

    contended = [
        s
        for s in window
        if len(s.blocked_queries) >= 3
        or any(b.blocked_duration_s >= BLOCKED_SECONDS for b in s.blocked_queries)
    ]
    if contended:
        worst = max(contended, key=lambda s: len(s.blocked_queries))
        blockers: dict[int, list[BlockedQuery]] = {}
        for blocked in worst.blocked_queries:
            blockers.setdefault(blocked.blocking_pid, []).append(blocked)
        top_pid, victims = max(blockers.items(), key=lambda kv: len(kv[1]))
        relation = next((v.relation for v in victims if v.relation), "")
        evidence.append(
            _make(
                "lock_contention",
                contended[0],
                (
                    f"{len(worst.blocked_queries)} queries blocked on {worst.database}"
                    + (f" (relation {relation})" if relation else "")
                    + f"; pid {top_pid} blocks {len(victims)} of them"
                ),
                0.5 + len(worst.blocked_queries) / 40,
                blocked=len(worst.blocked_queries),
                blocking_pid=top_pid,
                blocking_query=victims[0].blocking_query,
                relation=relation,
                longest_wait_s=round(max(b.blocked_duration_s for b in worst.blocked_queries), 1),
                first_seen=contended[0].captured_at.isoformat(),
            )
        )

    slow = [
        (s, q) for s in window for q in s.long_running_queries if q.duration_s >= LONG_QUERY_SECONDS
    ]
    if slow:
        snapshot, query = max(slow, key=lambda pair: pair[1].duration_s)
        evidence.append(
            _make(
                "long_running_query",
                slow[0][0],
                f"pid {query.pid} on {snapshot.database} running for {query.duration_s:.0f}s: "
                f"{query.query[:100]}",
                0.5,
                pid=query.pid,
                duration_s=round(query.duration_s, 1),
                state=query.state,
                query=query.query,
                first_seen=slow[0][0].captured_at.isoformat(),
            )
        )

    reference = before[-1] if before else window[0]
    new_deadlocks = window[-1].deadlocks_total - reference.deadlocks_total
    if new_deadlocks > 0:
        first = next(s for s in window if s.deadlocks_total > reference.deadlocks_total)
        evidence.append(
            _make(
                "deadlocks",
                first,
                f"{new_deadlocks} new deadlock(s) on {first.database} during the incident window",
                0.6,
                count=new_deadlocks,
                first_seen=first.captured_at.isoformat(),
            )
        )

    lagging = [s for s in window if (s.replication_lag_s or 0) >= REPLICATION_LAG_SECONDS]
    if lagging:
        worst = max(lagging, key=lambda s: s.replication_lag_s or 0)
        evidence.append(
            _make(
                "replication_lag",
                lagging[0],
                f"replica {worst.database} is {worst.replication_lag_s:.0f}s behind",
                0.5,
                lag_s=worst.replication_lag_s,
                first_seen=lagging[0].captured_at.isoformat(),
            )
        )
    return evidence


def collect_db_health(request: TriageRequest) -> list[Evidence]:
    by_database: dict[str, list[DbSnapshot]] = {}
    for snapshot in request.db_snapshots:
        by_database.setdefault(snapshot.database, []).append(snapshot)
    evidence: list[Evidence] = []
    for _, snapshots in sorted(by_database.items()):
        evidence.extend(analyse_snapshots(snapshots, request))
    return evidence
