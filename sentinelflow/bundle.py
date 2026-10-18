"""Load and save incident bundles (a folder of logs, metrics, snapshots and deploys)."""

from __future__ import annotations

import json
from pathlib import Path

from sentinelflow.models import TriageRequest


def load_bundle(path: str | Path) -> TriageRequest:
    root = Path(path)
    payload = json.loads((root / "incident.json").read_text())
    payload.pop("expected_root_cause", None)
    logs = root / "logs.jsonl"
    if logs.exists():
        payload["logs"] = [json.loads(line) for line in logs.read_text().splitlines() if line.strip()]
    for name in ("metrics", "db_snapshots", "deploys"):
        file = root / f"{name}.json"
        if file.exists():
            payload[name] = json.loads(file.read_text())
    return TriageRequest.model_validate(payload)


def write_bundle(request: TriageRequest, path: str | Path, expected_root_cause: str | None = None) -> None:
    root = Path(path)
    root.mkdir(parents=True, exist_ok=True)
    data = request.model_dump(mode="json")
    incident = {key: data[key] for key in ("service", "detected_at", "lookback_minutes", "topology")}
    incident["expected_root_cause"] = expected_root_cause
    (root / "incident.json").write_text(json.dumps(incident, indent=2) + "\n")
    (root / "logs.jsonl").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in data["logs"]))
    for name in ("metrics", "db_snapshots", "deploys"):
        (root / f"{name}.json").write_text(json.dumps(data[name], separators=(",", ":")) + "\n")
