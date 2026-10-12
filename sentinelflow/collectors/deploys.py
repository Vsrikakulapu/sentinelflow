"""Deployment-history collector.

Emits one ``deploy`` evidence item per rollout to the affected service or one
of its dependencies in the hours before detection. Deploys to unrelated
services are ignored: a rollout somewhere else in the fleet is not evidence.
"""

from __future__ import annotations

from datetime import timedelta

from sentinelflow.models import Evidence, TriageRequest

DEPLOY_LOOKBACK = timedelta(hours=6)


def collect_deploys(request: TriageRequest) -> list[Evidence]:
    scope = request.in_scope()
    earliest = request.detected_at - DEPLOY_LOOKBACK
    evidence: list[Evidence] = []
    for deploy in sorted(request.deploys, key=lambda d: d.deployed_at):
        if deploy.service not in scope:
            continue
        if not earliest <= deploy.deployed_at <= request.detected_at:
            continue
        minutes_before = (request.detected_at - deploy.deployed_at).total_seconds() / 60
        relation = "self" if deploy.service == request.service else "dependency"
        evidence.append(
            Evidence(
                id="",
                source="deploys",
                kind="deploy",
                service=deploy.service,
                observed_at=deploy.deployed_at,
                summary=(
                    f"{deploy.kind} deploy {deploy.version} to {deploy.service} "
                    f"{minutes_before:.0f} min before detection"
                    + (f": {deploy.summary}" if deploy.summary else "")
                ),
                severity=max(0.1, min(1.0, 1.0 - minutes_before / 360)),
                attributes={
                    "deploy_id": deploy.id,
                    "version": deploy.version,
                    "deploy_kind": deploy.kind,
                    "relation": relation,
                    "minutes_before_detection": round(minutes_before, 1),
                },
            )
        )
    return evidence
