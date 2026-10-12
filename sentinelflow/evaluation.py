"""Evaluation harness: attribution accuracy on generated incidents.

For every scenario and seed the pipeline is run under several *evidence
conditions* - all sources present, or one source withheld - and each outcome
is classified:

* ``correct``   - attributed to the true root cause (or, for negative
                  controls, correctly declined to attribute)
* ``abstained`` - declined to attribute although a cause existed
* ``wrong``     - attributed to something that was not the cause

``wrong`` is the number that matters operationally: a triage tool that sends
responders after the wrong system is worse than one that says "unknown".
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from sentinelflow.models import Attribution, TriageRequest
from sentinelflow.pipeline import triage
from sentinelflow.scenarios import NEGATIVE, POSITIVE, expected_root_cause, generate

CONDITIONS = ["all evidence", "no logs", "no metrics", "no database snapshots", "no deploy history"]
_FIELD = {"no logs": "logs", "no metrics": "metrics", "no database snapshots": "db_snapshots",
          "no deploy history": "deploys"}


def withhold(request: TriageRequest, condition: str) -> TriageRequest:
    field = _FIELD.get(condition)
    return request.model_copy(update={field: []}) if field else request


def classify(request: TriageRequest, expected: str | None) -> str:
    report = triage(request)
    attributed = report.root_cause.id if report.attribution is Attribution.ATTRIBUTED and report.root_cause else None
    if attributed == expected:
        return "correct"
    return "abstained" if attributed is None else "wrong"


@dataclass
class Row:
    condition: str
    group: str
    counts: Counter

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def rate(self, outcome: str) -> float:
        return self.counts[outcome] / self.total if self.total else 0.0


def run(seeds: int = 50) -> list[Row]:
    rows: list[Row] = []
    for condition in CONDITIONS:
        for group, kinds in (("incidents", POSITIVE), ("negative controls", NEGATIVE)):
            counts: Counter = Counter()
            for kind in kinds:
                for seed in range(seeds):
                    counts[classify(withhold(generate(kind, seed), condition), expected_root_cause(kind))] += 1
            rows.append(Row(condition, group, counts))
    return rows


def per_scenario(seeds: int = 50, condition: str = "all evidence") -> dict[str, Counter]:
    return {
        kind: Counter(
            classify(withhold(generate(kind, seed), condition), expected_root_cause(kind)) for seed in range(seeds)
        )
        for kind in POSITIVE + NEGATIVE
    }


def format_breakdown(seeds: int = 50) -> str:
    """Correct / abstained / wrong per scenario under each evidence condition."""
    lines = ["| Scenario | " + " | ".join(CONDITIONS) + " |", "|---|" + "---|" * len(CONDITIONS)]
    columns = [per_scenario(seeds, condition) for condition in CONDITIONS]
    for kind in POSITIVE + NEGATIVE:
        cells = [f"{c[kind]['correct']} / {c[kind]['abstained']} / {c[kind]['wrong']}" for c in columns]
        lines.append(f"| {kind} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def format_table(rows: list[Row]) -> str:
    lines = ["| Evidence available | Set | Runs | Correct | Abstained | Wrong |", "|---|---|---|---|---|---|"]
    for row in rows:
        lines.append(
            f"| {row.condition} | {row.group} | {row.total} | {row.rate('correct'):.1%} | "
            f"{row.rate('abstained'):.1%} | {row.rate('wrong'):.1%} |"
        )
    return "\n".join(lines)
