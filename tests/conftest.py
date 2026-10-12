from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinelflow.models import TriageRequest

T0 = datetime(2026, 3, 14, 14, 0, tzinfo=timezone.utc)


def at(minute: float) -> datetime:
    """Timestamp ``minute`` minutes relative to detection."""
    return T0 + timedelta(minutes=minute)


@pytest.fixture
def request_factory():
    def make(**overrides) -> TriageRequest:
        values = dict(
            service="checkout-api",
            detected_at=T0,
            lookback_minutes=30,
            topology={"checkout-api": ["payments-api"], "payments-api": ["bank-gateway"]},
        )
        values.update(overrides)
        return TriageRequest(**values)

    return make
