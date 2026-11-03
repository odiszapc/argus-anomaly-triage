from datetime import datetime, timedelta

from conftest import T0

from argus.correlate import Impact, Incident
from argus.ingest import ingest
from argus.model import Point, Signal
from argus.predict import Predictor
from argus.routing import Router
from argus.store import Store

DAY = 144


def ramp_rps(n: int) -> list[float]:
    """Night 40k, day 100k: the ramp happens around 06:00 UTC every day."""
    times = [T0 + timedelta(minutes=10 * i) for i in range(n)]
    return [100_000.0 if 6 <= t.hour < 20 else 40_000.0 for t in times]


def incident(start: datetime, resolved: datetime, severity: str = "SEV-1") -> Incident:
    pts = [Point(start, 5000, 5, 9, True)]
    s = Signal("log_burst", "redis", "Redis failure", start, start, start, start, 5000, 5, 9, 5000, {}, pts)
    i = Incident("cache-x", "ops", "cache", "DBA", "data_store", start, start, start, {"k": s}, status="resolved",
                 detected_at=start, resolved_at=resolved, severity=severity, impact=Impact(clients=10**6))
    i.task_id = "ARG-001"
    return i


class Book:
    def __init__(self, incidents):
        self.incidents = incidents


def test_recurrence_watch_predicts_next_ramp(dataset, tmp_path):
    ingest(dataset(points=4 * DAY, rps=ramp_rps(4 * DAY)), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb")
    start = datetime(2026, 8, 26, 11, 0)          # began under day-time load
    resolved = datetime(2026, 8, 26, 22, 0)        # resolved at night
    store.set_now(resolved)
    [p] = Predictor({}, Router.load(), store).tick(resolved, [], Book([incident(start, resolved)]))
    assert p.kind == "recurrence" and p.target == "ARG-001"
    assert p.window_start <= datetime(2026, 8, 27, 6, 10) <= p.window_end
    payload = p.payload("#app-alert-predictions")
    assert payload["channel"] == "#app-alert-predictions" and "ARG-001" in payload["text"]


def test_minor_incident_gets_no_prediction(dataset, tmp_path):
    ingest(dataset(points=4 * DAY, rps=ramp_rps(4 * DAY)), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb")
    resolved = datetime(2026, 8, 26, 22, 0)
    store.set_now(resolved)
    book = Book([incident(datetime(2026, 8, 26, 11, 0), resolved, severity="SEV-3")])
    assert Predictor({}, Router.load(), store).tick(resolved, [], book) == []


def test_incident_that_began_at_night_gets_no_prediction(dataset, tmp_path):
    ingest(dataset(points=4 * DAY, rps=ramp_rps(4 * DAY)), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb")
    resolved = datetime(2026, 8, 27, 4, 0)
    store.set_now(resolved)
    book = Book([incident(datetime(2026, 8, 27, 1, 0), resolved)])  # began under night load
    assert Predictor({}, Router.load(), store).tick(resolved, [], book) == []


def test_one_prediction_per_task_per_day(dataset, tmp_path):
    ingest(dataset(points=4 * DAY, rps=ramp_rps(4 * DAY)), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb")
    predictor = Predictor({}, Router.load(), store)
    first = datetime(2026, 8, 26, 22, 0)
    store.set_now(first)
    assert len(predictor.tick(first, [], Book([incident(datetime(2026, 8, 26, 11, 0), first)]))) == 1
    second = first + timedelta(hours=3)
    store.set_now(second)
    again = incident(datetime(2026, 8, 26, 12, 0), second)
    again.uid = "cache-y"
    assert predictor.tick(second, [], Book([again])) == []
