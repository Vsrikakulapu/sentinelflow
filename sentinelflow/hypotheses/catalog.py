"""Catalog of failure hypotheses.

A hypothesis is a claim about the root cause plus the *predictions* that claim
makes about the evidence. Each prediction is a check that returns
``supported``, ``contradicted`` or ``inconclusive`` and cites the evidence it
looked at. Nothing here assigns a confidence: that is the verifier's job
(``sentinelflow.verify``), so every hypothesis is scored by the same rules.

Design rules for checks:

* exactly one check per hypothesis is ``required`` - the signal without which
  the claim makes no sense (no deploy => cannot be a bad deploy)
* every hypothesis has a temporal check - a cause must not start after its effect
* absence of evidence is ``inconclusive``, never ``supported``
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sentinelflow.evidence import EvidenceSet, earliest, ids
from sentinelflow.models import CheckResult, Evidence, Verdict

SLACK = timedelta(minutes=3)
LATE = timedelta(minutes=5)
NEAR = timedelta(minutes=45)

S, C, I = Verdict.SUPPORTED, Verdict.CONTRADICTED, Verdict.INCONCLUSIVE


@dataclass
class Draft:
    id: str
    title: str
    rationale: str
    checks: list[CheckResult] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)

    def check(
        self,
        name: str,
        weight: float,
        verdict: Verdict,
        detail: str,
        evidence: list[Evidence] | None = None,
        *,
        required: bool = False,
    ) -> None:
        self.checks.append(
            CheckResult(
                name=name,
                verdict=verdict,
                weight=weight,
                required=required,
                detail=detail,
                evidence_ids=ids(evidence or []),
            )
        )


def _minutes(delta: timedelta) -> str:
    return f"{delta.total_seconds() / 60:.0f} min"


# ------------------------------------------------------------------- bad deploy


def bad_deploy(ev: EvidenceSet) -> Draft:
    service = ev.service
    draft = Draft(
        id="bad_deploy",
        title=f"Regression introduced by a deployment to {service}",
        rationale="A release changed behaviour; failures start right after the rollout.",
    )
    onset = ev.symptom_onset
    deploys = ev.find(kind="deploy", service=service)
    preceding = [d for d in deploys if onset is None or d.observed_at <= onset + SLACK]
    deploy = max(preceding, key=lambda d: d.observed_at) if preceding else None
    name = f"Deployment to {service} shortly before symptom onset"

    if not deploys:
        draft.check(name, 0.30, I, f"No deployment to {service} in the 6 hours before detection.", required=True)
    elif onset is None:
        draft.check(name, 0.30, I, "No symptom onset could be established to time the deployment against.", deploys, required=True)
    elif deploy is None:
        draft.check(name, 0.30, C, f"Symptoms began at {onset:%H:%M}, before every deployment to {service}.", deploys, required=True)
    elif onset - deploy.observed_at <= NEAR:
        draft.check(
            name, 0.30, S,
            f"{deploy.attributes['version']} rolled out {_minutes(onset - deploy.observed_at)} before symptoms began.",
            [deploy], required=True,
        )
    else:
        draft.check(
            name, 0.30, I,
            f"Latest deployment ({deploy.attributes['version']}) was {_minutes(onset - deploy.observed_at)} "
            "before onset - too far back to implicate by timing.",
            [deploy], required=True,
        )

    if deploy is not None:
        new_errors = [
            e for e in ev.find(kind="new_error_signature", service=service)
            if e.attributes.get("category") == "application" and e.observed_at >= deploy.observed_at - SLACK
        ]
        if new_errors:
            draft.check("New application error signatures first seen after the deployment", 0.35, S,
                        f"{len(new_errors)} error template(s) that never occurred before the rollout.", new_errors)
        else:
            draft.check("New application error signatures first seen after the deployment", 0.35, I,
                        "No new application-level error templates appeared after the rollout.")

        prior = [
            e for e in ev.find(kind=("metric_anomaly", "metric_trend", "error_spike"))
            + ev.find(source="database")
            if e.observed_at < deploy.observed_at - SLACK
        ]
        if prior:
            draft.check("No anomaly predates the deployment", 0.20, C,
                        f"{len(prior)} anomaly(ies) were already under way before the rollout.", prior)
        elif ev.symptoms():
            draft.check("No anomaly predates the deployment", 0.20, S,
                        "Every observed anomaly started at or after the rollout.", ev.symptoms())
        else:
            draft.check("No anomaly predates the deployment", 0.20, I, "No anomalies to order against the rollout.")

        dependency_trouble = [e for dep in ev.dependencies for e in ev.symptoms(dep)]
        if dependency_trouble:
            draft.check("Dependencies are healthy", 0.15, I,
                        "A dependency is also degraded, so the fault may not be local.", dependency_trouble)
        else:
            draft.check("Dependencies are healthy", 0.15, S, "No dependency shows errors or latency regressions.",
                        ev.symptoms()[:1])
        version = deploy.attributes["version"]
        draft.remediation = [
            f"Roll back {service} to the release before {version}.",
            "Diff that release against its predecessor, starting from the code path in the new error signature.",
            "Add an automated rollback gate on post-deploy error rate so the next regression reverts itself.",
        ]
    return draft


# ------------------------------------------------------ db connection exhaustion


def db_connection_exhaustion(ev: EvidenceSet) -> Draft:
    draft = Draft(
        id="db_connection_exhaustion",
        title="Database connection exhaustion",
        rationale="Sessions are not returned to the pool, so requests queue for a connection.",
    )
    # Direct proof is a server-side snapshot; a client pool pinned at its limit
    # is accepted as well, so the claim stays testable when no snapshot exists.
    saturation = ev.find(kind="connection_saturation") or ev.metric(
        "db_connections", kind="metric_saturation", direction=None)
    if saturation:
        draft.check("Database connection slots are saturated", 0.35, S, saturation[0].summary, saturation, required=True)
    else:
        draft.check("Database connection slots are saturated", 0.35, I,
                    "Neither a database snapshot nor the client pool shows connections at their limit.", required=True)

    pool_errors = ev.log_category("db_connection")
    draft.check("Application logs report connection-acquisition failures", 0.25, S if pool_errors else I,
                f"{sum(e.attributes['count'] for e in pool_errors)} pool / connection errors logged." if pool_errors
                else "No connection-pool errors in the application logs.", pool_errors)

    pool_metric = ev.metric("db_connections", kind=("metric_anomaly", "metric_saturation")) + ev.metric(
        "db_pool", kind=("metric_anomaly", "metric_saturation"))
    draft.check("Client-side pool metrics confirm saturation", 0.15, S if pool_metric else I,
                pool_metric[0].summary if pool_metric else "No pool metric deviates from baseline.", pool_metric)

    holders = ev.find(kind=("idle_in_transaction", "long_running_query"))
    draft.check("Sessions holding connections are identified", 0.10, S if holders else I,
                holders[0].summary if holders else "No idle-in-transaction or long-running sessions found.", holders)

    onset = ev.symptom_onset
    db_onset = earliest(saturation + pool_metric)
    # Periodic snapshots only bound the onset: it lies after the last healthy one.
    bounds = [datetime.fromisoformat(e.attributes["healthy_until"]) if e.attributes.get("healthy_until")
              else e.observed_at for e in saturation + pool_metric]
    name = "Saturation precedes user-visible symptoms"
    if onset is None or db_onset is None:
        draft.check(name, 0.15, I, "Not enough timing information to order the two.")
    elif db_onset <= onset + SLACK:
        draft.check(name, 0.15, S, f"Pool pressure from {db_onset:%H:%M}, symptoms from {onset:%H:%M}.",
                    saturation + pool_metric)
    elif min(bounds) > onset + LATE:
        draft.check(name, 0.15, C,
                    f"Symptoms began {_minutes(min(bounds) - onset)} before the pool could have filled, "
                    "so saturation is an effect.", saturation + pool_metric)
    else:
        draft.check(name, 0.15, I, "Snapshots are too coarse to order saturation against the symptoms.")

    draft.remediation = [
        "Terminate sessions stuck idle-in-transaction to free slots "
        "(SELECT pg_terminate_backend(pid) ... WHERE state = 'idle in transaction').",
        "Set idle_in_transaction_session_timeout so leaked sessions are reclaimed automatically.",
        "Find the code path that does not release its connection (missing close / commit on an error path).",
        "Size the client pool below max_connections, or put PgBouncer in front of the database.",
    ]
    return draft


# ------------------------------------------------------------ db lock contention


def db_lock_contention(ev: EvidenceSet) -> Draft:
    draft = Draft(
        id="db_lock_contention",
        title="Database lock contention",
        rationale="One session holds a lock that queues every query touching the same relation.",
    )
    locks = ev.find(kind="lock_contention")
    lock_logs = ev.log_category("db_lock") + ev.find(kind="deadlocks")
    # Blocked sessions in a snapshot are direct proof; lock-timeout errors raised
    # by the database are accepted too, so the claim survives a missing snapshot.
    waits = locks or lock_logs
    if waits:
        draft.check("Queries are blocked waiting on locks", 0.35, S, waits[0].summary, waits, required=True)
    else:
        draft.check("Queries are blocked waiting on locks", 0.35, I,
                    "No blocked queries in database snapshots and no lock-timeout errors in the logs.", required=True)

    draft.check("Lock timeouts or deadlocks are reported", 0.20, S if lock_logs else I,
                lock_logs[0].summary if lock_logs else "No lock-timeout or deadlock errors observed.", lock_logs)

    blockers = ev.find(kind="long_running_query")
    if locks and locks[0].attributes.get("blocking_pid") is not None and blockers:
        draft.check("The blocking session is identified", 0.15, S,
                    f"pid {locks[0].attributes['blocking_pid']} holds the lock: "
                    f"{str(locks[0].attributes.get('blocking_query', ''))[:80]}", blockers + locks)
    else:
        draft.check("The blocking session is identified", 0.15, I, "No single long-running blocker was captured.")

    latency = ev.metric("latency")
    cpu = ev.metric("cpu", kind=("metric_anomaly", "metric_saturation"))
    if latency and not cpu:
        draft.check("Latency rises while CPU stays flat (waiting, not working)", 0.15, S, latency[0].summary, latency)
    else:
        draft.check("Latency rises while CPU stays flat (waiting, not working)", 0.15, I,
                    "CPU is also elevated, so slowness is not explained by waiting alone." if cpu
                    else "No latency regression recorded.", cpu)

    onset = ev.symptom_onset or ev.request.detected_at
    migrations = ev.find(kind="deploy", where=lambda d: d.attributes.get("deploy_kind") == "migration"
                         and onset - NEAR <= d.observed_at <= onset + SLACK)
    draft.check("A schema migration ran just before onset", 0.15, S if migrations else I,
                migrations[0].summary if migrations else "No migration in the 45 minutes before onset.", migrations)

    target = f"pid {locks[0].attributes['blocking_pid']}" if locks else "the blocking session"
    draft.remediation = [
        f"Cancel {target} (SELECT pg_cancel_backend(pid)); escalate to pg_terminate_backend if it does not release.",
        "Set lock_timeout on migrations so DDL fails fast instead of queueing behind traffic.",
        "Rewrite the schema change to avoid long ACCESS EXCLUSIVE locks (CREATE INDEX CONCURRENTLY, batched backfills).",
        "Keep transactions short; move slow work outside the transaction that holds the lock.",
    ]
    return draft


# ------------------------------------------------------------------ memory leak


def memory_leak(ev: EvidenceSet) -> Draft:
    service = ev.service
    draft = Draft(
        id="memory_leak",
        title=f"Memory leak in {service}",
        rationale="Memory grows steadily until the process is killed and restarts.",
    )
    growth = ev.metric("memory", kind="metric_trend", direction=None)
    if growth:
        draft.check("Memory grows steadily over a long period", 0.35, S, growth[0].summary, growth, required=True)
    else:
        draft.check("Memory grows steadily over a long period", 0.35, I,
                    f"{service} memory shows no sustained linear growth.", required=True)

    kills = ev.log_category("oom") + ev.metric("container_restarts") + ev.metric("restarts")
    draft.check("Out-of-memory kills or restarts are observed", 0.30, S if kills else I,
                kills[0].summary if kills else "No OOM errors or container restarts recorded.", kills)

    onset = ev.symptom_onset
    if growth and onset is not None and growth[0].observed_at <= onset - timedelta(minutes=30):
        draft.check("Growth began long before symptoms (gradual, not a step)", 0.20, S,
                    f"Growth visible {_minutes(onset - growth[0].observed_at)} before the first symptom.", growth)
    else:
        draft.check("Growth began long before symptoms (gradual, not a step)", 0.20, I,
                    "Cannot show that growth predates the symptoms by a wide margin.")

    limit = ev.metric("memory", kind="metric_saturation", direction=None)
    draft.check("Memory reached the container limit", 0.15, S if limit else I,
                limit[0].summary if limit else "Memory did not reach its configured limit.", limit)

    draft.remediation = [
        f"Restart {service} pods one at a time to restore headroom (temporary relief only).",
        "Capture a heap dump / allocation profile from a pod before it is restarted.",
        "Bisect to the release where the growth slope first appears and review caches and listeners added there.",
        "Alert on memory growth rate, not just the limit, to catch the next leak hours earlier.",
    ]
    return draft


# ---------------------------------------------------- upstream dependency failure


def upstream_dependency_failure(ev: EvidenceSet) -> Draft:
    service = ev.service
    troubled = {dep: ev.symptoms(dep) for dep in ev.dependencies}
    troubled = {dep: items for dep, items in troubled.items() if items}
    dependency = max(troubled, key=lambda d: max(e.severity for e in troubled[d])) if troubled else None
    draft = Draft(
        id="upstream_dependency_failure",
        title=f"Failure in upstream dependency {dependency}" if dependency else "Failure in an upstream dependency",
        rationale=f"{service} is healthy itself but fails because a service it calls is failing.",
    )
    name = "A dependency is itself degraded"
    if dependency is None:
        draft.check(name, 0.35, I,
                    "No dependency shows errors or latency regressions." if ev.dependencies
                    else f"No dependencies are declared for {service}.", required=True)
        return draft
    dep_evidence = troubled[dependency]
    draft.check(name, 0.35, S, dep_evidence[0].summary, dep_evidence, required=True)

    upstream_logs = ev.log_category("upstream")
    naming = [e for e in upstream_logs if dependency in e.attributes.get("mentions", [])]
    if naming:
        draft.check(f"{service} logs failed calls to {dependency}", 0.25, S,
                    f"{sum(e.attributes['count'] for e in naming)} failed calls to {dependency} logged.", naming)
    else:
        draft.check(f"{service} logs failed calls to {dependency}", 0.25, I,
                    "Upstream errors are logged but do not name this dependency." if upstream_logs
                    else "No upstream-call failures in the application logs.", upstream_logs)

    onset, dep_onset = ev.symptom_onset, earliest(dep_evidence)
    if onset is None or dep_onset is None:
        draft.check("The dependency degraded first", 0.25, I, "Not enough timing information to order the two.")
    elif dep_onset <= onset + SLACK:
        draft.check("The dependency degraded first", 0.25, S,
                    f"{dependency} degraded at {dep_onset:%H:%M}, {service} at {onset:%H:%M}.", dep_evidence)
    elif dep_onset > onset + LATE:
        draft.check("The dependency degraded first", 0.25, C,
                    f"{service} was already failing {_minutes(dep_onset - onset)} before {dependency} degraded.", dep_evidence)
    else:
        draft.check("The dependency degraded first", 0.25, I, "Both degraded too close together to order.")

    local = ev.self_deploy_near_onset() + ev.metric("cpu", kind="metric_saturation", direction=None) + ev.metric(
        "memory", kind="metric_saturation", direction=None)
    if local:
        draft.check(f"No local cause in {service}", 0.15, C,
                    "A local change or resource limit could explain the failure on its own.", local)
    else:
        draft.check(f"No local cause in {service}", 0.15, S,
                    f"No recent deployment to {service} and no resource saturation.", ev.symptoms()[:1])

    dep_deploys = ev.find(kind="deploy", service=dependency,
                          where=lambda d: dep_onset is not None and dep_onset - NEAR <= d.observed_at <= dep_onset + SLACK)
    draft.remediation = [
        f"Page the team that owns {dependency} and share this report.",
        (f"{dependency} deployed {dep_deploys[-1].attributes['version']} just before it degraded - ask them to roll back."
         if dep_deploys else f"Check {dependency}'s own dashboards for the underlying fault."),
        f"Serve a degraded response or open the circuit breaker for calls to {dependency}.",
        "Review timeouts and retry budgets so a failing dependency cannot exhaust this service's threads.",
    ]
    return draft


# ------------------------------------------------------------- traffic overload


def traffic_overload(ev: EvidenceSet) -> Draft:
    service = ev.service
    draft = Draft(
        id="traffic_overload",
        title=f"Traffic surge beyond {service} capacity",
        rationale="Request volume exceeded what the current replicas can serve.",
    )
    surge = ev.metric("request_rate")
    if surge:
        draft.check("Request rate is far above baseline", 0.35, S, surge[0].summary, surge, required=True)
    else:
        draft.check("Request rate is far above baseline", 0.35, I, "Request rate is within its normal range.", required=True)

    cpu = ev.metric("cpu", kind=("metric_anomaly", "metric_saturation"))
    draft.check("CPU is saturated", 0.25, S if cpu else I,
                cpu[0].summary if cpu else "CPU utilisation is not elevated.", cpu)

    onset, surge_onset = ev.symptom_onset, earliest(surge)
    if onset is None or surge_onset is None:
        draft.check("Degradation follows the surge", 0.20, I, "Not enough timing information to order the two.")
    elif onset >= surge_onset - SLACK:
        draft.check("Degradation follows the surge", 0.20, S,
                    f"Traffic rose at {surge_onset:%H:%M}; symptoms began at {onset:%H:%M}.", surge + ev.symptoms()[:1])
    elif onset < surge_onset - LATE:
        draft.check("Degradation follows the surge", 0.20, C,
                    f"Symptoms began {_minutes(surge_onset - onset)} before traffic rose.", surge)
    else:
        draft.check("Degradation follows the surge", 0.20, I, "Surge and symptoms started too close together to order.")

    code_errors = [e for e in ev.find(kind="new_error_signature", service=service)
                   if e.attributes.get("category") == "application"]
    local = ev.self_deploy_near_onset() + code_errors
    if local:
        draft.check("No code change explains the failures", 0.20, C,
                    "A recent deployment or new application errors point at a code regression instead.", local)
    else:
        draft.check("No code change explains the failures", 0.20, S,
                    "No recent deployment and no new application error signatures.", surge[:1])

    draft.remediation = [
        f"Scale out {service} (raise replicas / HPA maximum) until CPU drops below target.",
        "Enable rate limiting or load shedding for the heaviest client so the service degrades gracefully.",
        "Establish whether the surge is legitimate (launch, campaign) or abusive (retry storm, scraper).",
        "Load-test to find the per-replica ceiling and set autoscaling thresholds below it.",
    ]
    return draft


CATALOG: list[Callable[[EvidenceSet], Draft]] = [
    bad_deploy,
    db_connection_exhaustion,
    db_lock_contention,
    memory_leak,
    upstream_dependency_failure,
    traffic_overload,
]
