from datetime import datetime, timedelta

from argus.correlate import Incident
from argus.dedup import Dedup, text_vector
from argus.engine import Memory, TaskRecord
from argus.model import Point, Signal
from argus.routing import Router
from argus.triage import fallback_triage

T = datetime(2026, 9, 2, 11, 20)
REDIS, UNEXPECTED, LOADING, TOPO = "Redis failure", "Unexpected Redis exception", "LOADING Valkey is loading", "Topology is closed"


def inc(uid: str, component: str, labels: list[str], start: datetime, new: tuple[str, ...] = ()) -> Incident:
    sigs = {}
    for i, label in enumerate(labels):
        pts = [Point(start, 1000, 5, 9, True)]
        sigs[f"k{i}"] = Signal("log_burst", label.replace(" ", "")[:10], label, start, start, start, start, 1000, 5, 9,
                               1000 - i, {"new_template": label in new}, pts)
    role = Router.load().get(component).role
    return Incident(uid, "ops", component, role, Router.load().get(component).family, start, start, start, sigs,
                    status="open", detected_at=start)


def memory_with(parent: Incident, last_active: datetime) -> Memory:
    mem = Memory(incidents=[parent])
    parent.task_id = "ARG-001"
    mem.tasks["ARG-001"] = TaskRecord("ARG-001", parent.uid, fallback_triage(parent, Router.load()), parent.fingerprint(),
                                      parent.start, 10, 10, last_active=last_active)
    return mem


def test_repeat_within_window_is_duplicate():
    parent = inc("a", "cache", [REDIS, UNEXPECTED], T)
    new = inc("b", "cache", [REDIS], T + timedelta(hours=20))
    assert Dedup({}, Router.load()).match(new, None, memory_with(parent, T + timedelta(hours=2)), new.start).task_id == "ARG-001"


def test_other_component_is_new():
    parent = inc("a", "cache", [REDIS], T)
    new = inc("b", "app_lock", ["Timeout <N> wait exceeded"], T + timedelta(hours=3))
    assert Dedup({}, Router.load()).match(new, None, memory_with(parent, T + timedelta(hours=1)), new.start) is None


def test_new_failure_mode_is_new_task():
    parent = inc("a", "cache", [REDIS, UNEXPECTED], T)
    new = inc("b", "cache", [LOADING, REDIS], T + timedelta(hours=30), new=(LOADING,))
    assert Dedup({}, Router.load()).match(new, None, memory_with(parent, T + timedelta(hours=2)), new.start) is None


def test_old_task_outside_window_is_new():
    parent = inc("a", "cache", [REDIS], T)
    new = inc("b", "cache", [REDIS], T + timedelta(hours=90))
    assert Dedup({}, Router.load()).match(new, None, memory_with(parent, T + timedelta(hours=1)), new.start) is None


def test_same_family_counts_as_same_problem():
    parent = inc("a", "database", [TOPO], T)
    new = inc("b", "database", [TOPO, REDIS], T + timedelta(hours=24))
    assert Dedup({}, Router.load()).match(new, None, memory_with(parent, T + timedelta(hours=3)), new.start) is not None


def test_text_vectors_are_similar_for_near_duplicates():
    a, b, c = text_vector("Redis failure"), text_vector("Unexpected Redis exception"), text_vector("Topology is closed")
    assert float(a @ b) > float(a @ c)


def test_dominant_cause_seen_before_is_repeat():
    parent = inc("a", "database", [TOPO, "Mongo DB failure", "connection <monitor> to <IP> timed out", "Query execution"], T)
    new = inc("b", "database", [TOPO, "Remote mongod failure!", "Query execution was interrupted x", "Mongo y"],
              T + timedelta(hours=24))
    assert Dedup({"embeddings": False}, Router.load()).match(
        new, None, memory_with(parent, T + timedelta(hours=3)), new.start) is not None
