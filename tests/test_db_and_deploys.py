from conftest import at

from sentinelflow.collectors.db_health import (
    SQL_BLOCKED,
    SQL_CONNECTION_STATES,
    SQL_DEADLOCKS,
    SQL_LOCK_WAITERS,
    SQL_LONG_RUNNING,
    SQL_MAX_CONNECTIONS,
    SQL_REPLICATION_LAG,
    PostgresHealthProbe,
    collect_db_health,
)
from sentinelflow.collectors.deploys import collect_deploys
from sentinelflow.models import BlockedQuery, DbSnapshot, DeployRecord, LongRunningQuery


def snap(minute, **kw):
    values = dict(captured_at=at(minute), database="orders-db", max_connections=60, active=15, idle=10)
    values.update(kw)
    return DbSnapshot(**values)


def test_healthy_database_produces_no_evidence(request_factory):
    assert collect_db_health(request_factory(db_snapshots=[snap(m) for m in range(-60, 1, 5)])) == []


def test_connection_saturation_records_when_it_was_last_healthy(request_factory):
    snapshots = [snap(-20), snap(-15), snap(-10, idle_in_transaction=30), snap(-5, idle_in_transaction=33)]
    evidence = {e.kind: e for e in collect_db_health(request_factory(db_snapshots=snapshots))}
    saturation = evidence["connection_saturation"]
    assert saturation.observed_at == at(-10)
    assert saturation.attributes["used"] == 58
    assert saturation.attributes["healthy_until"] == at(-15).isoformat()
    assert evidence["idle_in_transaction"].attributes["sessions"] == 33


def test_lock_contention_names_the_session_blocking_the_most_queries(request_factory):
    blocked = [BlockedQuery(blocked_pid=100 + i, blocking_pid=4242, blocked_duration_s=40, relation="orders") for i in range(5)]
    blocked.append(BlockedQuery(blocked_pid=900, blocking_pid=77, blocked_duration_s=2, relation="users"))
    snapshots = [snap(-10), snap(-5, blocked_queries=blocked,
                                 long_running_queries=[LongRunningQuery(pid=4242, duration_s=300, query="ALTER TABLE orders")])]
    evidence = {e.kind: e for e in collect_db_health(request_factory(db_snapshots=snapshots))}
    assert evidence["lock_contention"].attributes["blocking_pid"] == 4242
    assert evidence["lock_contention"].attributes["relation"] == "orders"
    assert evidence["long_running_query"].attributes["pid"] == 4242


def test_only_new_deadlocks_count(request_factory):
    steady = [snap(-40, deadlocks_total=7), snap(-10, deadlocks_total=7), snap(-5, deadlocks_total=7)]
    assert collect_db_health(request_factory(db_snapshots=steady)) == []
    rising = [snap(-40, deadlocks_total=7), snap(-10, deadlocks_total=7), snap(-5, deadlocks_total=9)]
    evidence = collect_db_health(request_factory(db_snapshots=rising))
    assert [(e.kind, e.attributes["count"]) for e in evidence] == [("deadlocks", 2)]


class FakeCursor:
    def __init__(self, rows):
        self._rows, self._result, self.executed = rows, [], []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        self._result = self._rows[sql]

    def fetchall(self):
        return self._result


class FakeConnection:
    def __init__(self, rows):
        self.cursor_obj = FakeCursor(rows)

    def cursor(self):
        return self.cursor_obj


def test_probe_maps_pg_stat_activity_rows_to_a_snapshot():
    connection = FakeConnection({
        SQL_MAX_CONNECTIONS: [(100,)],
        SQL_CONNECTION_STATES: [("active", 12), ("idle", 30), ("idle in transaction", 4), ("idle in transaction (aborted)", 1)],
        SQL_LOCK_WAITERS: [(3,)],
        SQL_LONG_RUNNING: [(4242, 310.5, "active", "ALTER TABLE orders", None)],
        SQL_BLOCKED: [(501, 4242, 42.0, "relation", "orders", "ALTER TABLE orders")],
        SQL_DEADLOCKS: [(2,)],
        SQL_REPLICATION_LAG: [(None,)],
    })
    snapshot = PostgresHealthProbe(connection, database="orders-db").snapshot(long_query_seconds=5)
    assert (snapshot.max_connections, snapshot.active, snapshot.idle, snapshot.idle_in_transaction) == (100, 12, 30, 5)
    assert snapshot.connections_used == 47 and snapshot.waiting_on_lock == 3
    assert snapshot.blocked_queries[0].blocking_pid == 4242
    assert snapshot.long_running_queries[0].duration_s == 310.5
    assert snapshot.deadlocks_total == 2 and snapshot.replication_lag_s is None
    assert (SQL_LONG_RUNNING, {"min_seconds": 5}) in connection.cursor_obj.executed


def test_deploys_are_scoped_to_the_service_and_its_transitive_dependencies(request_factory):
    deploys = [
        DeployRecord(id="1", service="checkout-api", version="v2", deployed_at=at(-12)),
        DeployRecord(id="2", service="bank-gateway", version="v8", deployed_at=at(-50), kind="config"),
        DeployRecord(id="3", service="search-api", version="v3", deployed_at=at(-5)),
        DeployRecord(id="4", service="checkout-api", version="v1", deployed_at=at(-600)),
        DeployRecord(id="5", service="checkout-api", version="v3", deployed_at=at(+4)),
    ]
    evidence = collect_deploys(request_factory(deploys=deploys))
    assert [(e.service, e.attributes["relation"]) for e in evidence] == [("bank-gateway", "dependency"), ("checkout-api", "self")]
    assert evidence[1].attributes["minutes_before_detection"] == 12.0
