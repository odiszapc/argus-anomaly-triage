from datetime import datetime, timedelta

from argus.correlate import Impact, IncidentBook, IncidentCfg
from argus.detect.security import BotFeatures
from argus.model import Point, Signal
from argus.routing import Router

T = datetime(2026, 9, 2, 0, 10)
REST = "Rest error: Operation timed out after <N> milliseconds with <N> bytes received"
SEEDBOX = BotFeatures("RapidSeedbox Ltd", 0.52, 1.0, 0.0, 0.98, 17764)


def at(i: int) -> datetime:
    return T + timedelta(minutes=10 * i)


def sig(kind: str, label: str, start: int, end: int, value: float = 1000.0, base: float = 10.0,
        key: str | None = None, **attrs) -> Signal:
    points = [Point(at(i), value, base, 10.0, True) for i in range(start, end + 1)]
    return Signal(kind, key or label, label, at(start), at(end), at(start), at(start), value, base, 10.0,
                  value * (end - start + 1), dict(attrs), points)


class FakeProbe:
    def __init__(self, clients: int = 20_000, level=None, bot: BotFeatures | None = None):
        self.clients, self.level_fn, self.bot_features = clients, level or (lambda tpl, now: 0.0), bot

    def impact(self, incident, now) -> Impact:
        return Impact(lines=self.clients * 3, n5xx=self.clients * 3, clients=self.clients, users=self.clients // 10)

    def level(self, tpl_id: str, now: datetime) -> float:
        return self.level_fn(tpl_id, now)

    def bot(self, incident, now) -> BotFeatures | None:
        return self.bot_features

    def typical(self, tpl_id: str, before: datetime) -> float:
        return float("inf")  # unknown: the signal's own baseline decides


def run(signals: list[Signal], ticks: int, probe: FakeProbe | None = None) -> tuple[IncidentBook, list]:
    book = IncidentBook(Router.load(), probe or FakeProbe(), IncidentCfg())
    events = []
    for i in range(ticks):
        now = at(i)
        visible = [v for v in (s.truncate(now) for s in signals) if v and v.end >= now - timedelta(hours=2)]
        events += book.step(visible, now)
    return book, events


def opened(events) -> list:
    return [e.incident for e in events if e.kind == "opened"]


def test_overlapping_symptoms_attach_to_cause():
    book, events = run([sig("log_burst", REST, 0, 5), sig("log_burst", "LOADING Valkey is loading the dataset in memory", 1, 2)], 20)
    [inc] = opened(events)
    assert (inc.component, inc.role, len(inc.signals)) == ("cache", "DBA", 2)
    assert inc.detected_at == at(1)
    assert [e.kind for e in events if e.kind != "updated"] == ["opened", "resolved"]


def test_role_priority():
    _, events = run([sig("log_burst", "Topology is closed", 0, 3),
                     sig("log_burst", 'Value "<S>"is not valid for the enum "<S>"', 1, 2)], 20)
    [inc] = opened(events)
    assert (inc.component, inc.role, len(inc.signals)) == ("database", "DBA", 2)


def test_long_regression_is_one_incident():
    wait = "Timeout <N> wait exceeded"
    probe = FakeProbe(level=lambda tpl, now: 500.0 if now < at(110) else 5.0)
    book, events = run([sig("log_burst", wait, 10, 12), sig("log_burst", wait, 40, 41), sig("log_burst", wait, 100, 102)],
                       130, probe)
    [inc] = opened(events)
    assert inc.component == "app_lock" and len(inc.signals) == 3
    resolved = [e for e in events if e.kind == "resolved"]
    assert len(resolved) == 1 and resolved[0].at >= at(110)


def test_different_cause_families_split():
    _, events = run([sig("log_burst", "Topology is closed", 0, 5),
                     sig("log_burst", "Rest error: Could not resolve host: backend-service-test<N>-headless", 2, 4)], 20)
    assert sorted(i.role for i in opened(events)) == ["DBA", "PaaS Engineer"]


def test_short_blip_does_not_open():
    _, events = run([sig("log_burst", REST, 0, 0)], 20, FakeProbe(clients=300))
    assert [e.kind for e in events] == ["blip"]


def test_recurring_blips_open_incident():
    _, events = run([sig("log_burst", REST, 0, 0), sig("log_burst", REST, 30, 30), sig("log_burst", REST, 60, 60)],
                    80, FakeProbe(clients=300))
    [inc] = opened(events)
    assert inc.reason == "recurring" and inc.detected_at == at(61)


def test_country_shift_is_its_own_incident():
    _, events = run([sig("log_burst", "Topology is closed", 0, 10),
                     sig("country_shift", "BR", 2, 12, value=2000, base=1000, key="BR", direction="up")], 40)
    assert sorted((i.component, i.role) for i in opened(events)) == [("country_traffic", "SEO Specialist"),
                                                                     ("database", "DBA")]


def test_rps_artifacts_fold_into_one_task():
    artifacts = [sig("rps_artifact", "RPS", i, i, value=160_000, base=80_000, key="rps") for i in (0, 50, 100, 150, 200)]
    book, events = run(artifacts, 210)
    [inc] = opened(events)
    assert (inc.component, inc.role, inc.detected_at) == ("observability", "PaaS Engineer", at(100))
    assert len(inc.signals) == 5 and len(book.incidents) == 1


def test_bot_features_route_to_security():
    _, events = run([sig("log_burst", "Adapter failure", 0, 1)], 20, FakeProbe(bot=SEEDBOX))
    [inc] = opened(events)
    assert (inc.component, inc.role) == ("abuse", "Security Lead")


def test_upstream_under_load_routes_to_paas():
    _, events = run([sig("log_burst", REST, 0, 5), sig("rps_shift", "RPS", 0, 3, value=110_000, base=80_000, key="rps")], 20)
    [inc] = opened(events)
    assert (inc.component, inc.role) == ("capacity", "PaaS Engineer")


def test_impact_counts_clients_not_lines(dataset, tmp_path):
    from argus.correlate import Incident
    from argus.ingest import ingest
    from argus.probe import StoreProbe
    from argus.store import Store
    from conftest import T0 as DATA_T0
    from conftest import log_line

    t = DATA_T0 + timedelta(minutes=30)
    logs = [log_line(t + timedelta(seconds=i), "Redis failure", user_id="u1") for i in range(3)]
    logs += [log_line(t + timedelta(seconds=10), "Redis failure", ip="10.9.0.1", country="BR"),
             log_line(t + timedelta(seconds=11), "Redis failure", ip="10.9.0.2", country="BR"),
             log_line(t + timedelta(seconds=12), "Other thing", ip="10.9.0.3")]
    ingest(dataset(logs=logs, points=12), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb")
    tpl_id = store.scalar("SELECT tpl_id FROM templates WHERE tpl = 'Redis failure'")
    s = sig("log_burst", "Redis failure", 0, 0, key=tpl_id)
    s.start = s.end = DATA_T0 + timedelta(minutes=40)
    incident = Incident("x", "ops", "cache", "DBA", "data_store", s.start, s.end, s.end, {"k": s})
    now = DATA_T0 + timedelta(hours=1)
    store.set_now(now)
    impact = StoreProbe(store).impact(incident, now)
    assert (impact.lines, impact.clients, impact.users) == (5, 3, 1)
    assert impact.top_countries[0] == ("BR", 2)
    assert impact.requests > 0 and 0 < impact.error_rate < 1


def test_metric_only_traffic_shift_opens():
    _, events = run([sig("traffic_shift", "Трафик", 0, 5, value=60_000, base=100_000, key="traffic")], 20,
                    FakeProbe(clients=0))
    [inc] = opened(events)
    assert (inc.component, inc.role, inc.reason) == ("capacity", "PaaS Engineer", "metric deviation")


def test_app_family_does_not_merge_different_components():
    _, events = run([sig("log_burst", "Twitter integration error (x)", 0, 3),
                     sig("log_burst", "Timeout <N> wait exceeded", 1, 5)], 20)
    assert sorted(i.component for i in opened(events)) == ["app_lock", "external"]


def test_long_regression_does_not_absorb_unrelated_symptoms():
    wait = "Timeout <N> wait exceeded"
    probe = FakeProbe(level=lambda tpl, now: 500.0 if now < at(100) else 5.0)
    book, events = run([sig("log_burst", wait, 10, 12), sig("log_burst", REST, 50, 52)], 120, probe)
    assert sorted(i.component for i in opened(events)) == ["app_lock", "upstream"]


def test_signal_after_short_gap_joins_open_incident():
    _, events = run([sig("log_burst", "LOADING Valkey is loading the dataset in memory", 0, 2),
                     sig("log_burst", REST, 6, 8)], 30)
    [inc] = opened(events)
    assert len(inc.signals) == 2


def test_recurring_needs_some_impact():
    _, events = run([sig("log_burst", REST, 0, 0), sig("log_burst", REST, 30, 30), sig("log_burst", REST, 60, 60)],
                    80, FakeProbe(clients=2))
    assert opened(events) == []


def test_country_drop_during_outage_is_a_symptom():
    _, events = run([sig("log_burst", "Topology is closed", 0, 10),
                     sig("country_shift", "US", 3, 9, value=4000, base=8000, key="US", direction="down")],
                    40, FakeProbe(clients=200_000))
    [inc] = opened(events)
    assert inc.component == "database" and any(s.kind == "country_shift" for s in inc.signals.values())


def test_country_shift_survives_a_pause():
    br = [sig("country_shift", "BR", 0, 27, value=2000, base=1000, key="BR", direction="up"),
          sig("country_shift", "BR", 46, 100, value=2000, base=1000, key="BR", direction="up")]
    _, events = run(br, 120)
    assert len(opened(events)) == 1


def test_cause_soon_after_open_reassigns():
    _, events = run([sig("log_burst", REST, 0, 10), sig("log_burst", "LOADING Valkey is loading the dataset in memory", 3, 4)], 30)
    [inc] = opened(events)
    assert (inc.component, inc.role) == ("cache", "DBA")
    assert any(e.kind == "updated" and "DBA" in e.detail for e in events)


def test_cause_long_after_open_starts_new_incident():
    _, events = run([sig("log_burst", REST, 0, 20), sig("log_burst", "LOADING Valkey is loading the dataset in memory", 10, 11)], 40)
    assert sorted(i.component for i in opened(events)) == ["cache", "upstream"]


def test_anchor_uses_level_before_incident():
    wait = "Timeout <N> wait exceeded"
    probe = FakeProbe(level=lambda tpl, now: 1000.0 if now < at(90) else 100.0)
    probe.typical = lambda tpl, before: 300.0  # the adaptive baseline (4000) already absorbed the regression
    book, events = run([sig("log_burst", wait, 10, 12, value=20_000, base=4000)], 120, probe)
    [resolved] = [e for e in events if e.kind == "resolved"]
    assert resolved.at >= at(90)


def test_weak_familiar_cause_does_not_take_over():
    wait = sig("log_burst", "Timeout <N> wait exceeded", 2, 2, value=3000, new_template=False)
    _, events = run([sig("log_burst", REST, 0, 5, value=40_000), wait,
                     sig("rps_shift", "RPS", 0, 3, value=110_000, base=80_000, key="rps")], 20)
    [inc] = opened(events)
    assert (inc.component, inc.role) == ("capacity", "PaaS Engineer")


def test_new_cause_takes_over_even_when_small():
    monitor = sig("log_burst", "connection <monitor> to <IP> timed out", 1, 1, value=300, new_template=True)
    _, events = run([sig("log_burst", REST, 0, 5, value=400_000), monitor], 20)
    [inc] = opened(events)
    assert (inc.component, inc.role) == ("database", "DBA")


def test_severity_follows_peak_error_rate():
    class Peaky(FakeProbe):
        def impact(self, incident, now):
            return Impact(lines=9000, n5xx=9000, clients=2000, users=100, peak_error_rate=0.02)
    _, events = run([sig("log_burst", REST, 0, 3)], 20, Peaky())
    [inc] = opened(events)
    assert inc.severity == "SEV-1"


def test_familiar_one_bucket_cause_does_not_reassign_open_incident():
    _, events = run([sig("rps_shift", "RPS", 0, 4, value=110_000, base=80_000, key="rps"),
                     sig("log_burst", REST, 3, 12, value=20_000),
                     sig("log_burst", "Timeout <N> wait exceeded", 4, 4, value=3500, new_template=False)], 30)
    [inc] = opened(events)
    assert (inc.component, inc.role) == ("capacity", "PaaS Engineer")


def test_major_incident_survives_a_longer_pause():
    class Major(FakeProbe):
        def impact(self, incident, now):
            return Impact(lines=10**6, n5xx=10**6, clients=900_000, users=10**5, peak_error_rate=0.02)
    _, events = run([sig("log_burst", "Topology is closed", 0, 5), sig("log_burst", REST, 13, 15)], 40, Major())
    assert len(opened(events)) == 1  # 70 minutes of quiet do not end a SEV-1


def test_abuse_is_at_least_sev2():
    _, events = run([sig("log_burst", "Adapter failure", 0, 1)], 20, FakeProbe(clients=6000, bot=SEEDBOX))
    [inc] = opened(events)
    assert inc.severity == "SEV-2"


def test_regression_reopens_after_a_dip():
    wait = "Timeout <N> wait exceeded"
    level = lambda tpl, now: 5.0 if at(50) <= now < at(60) or now >= at(100) else 500.0  # noqa: E731
    _, events = run([sig("log_burst", wait, 10, 12)], 130, FakeProbe(level=level))
    kinds = [e.kind for e in events if e.kind != "updated"]
    assert kinds == ["opened", "resolved", "reopened", "resolved"]
    reopened = next(e for e in events if e.kind == "reopened")
    assert at(60) <= reopened.at <= at(63)


def test_same_cause_returning_revives_resolved_incident():
    wait = "Timeout <N> wait exceeded"
    level = lambda tpl, now: 500.0 if at(10) <= now < at(50) or now >= at(80) else 5.0  # noqa: E731
    book, events = run([sig("log_burst", wait, 10, 12), sig("log_burst", wait, 81, 82)], 100, FakeProbe(level=level))
    assert len(opened(events)) == 1 and len(book.incidents) == 1
    assert [e.kind for e in events if e.kind != "updated"][:3] == ["opened", "resolved", "reopened"]


def test_burst_of_same_cause_after_resolve_is_a_new_incident():
    wait = "Timeout <N> wait exceeded"
    book, events = run([sig("log_burst", wait, 10, 12), sig("log_burst", wait, 30, 31)], 60,
                       FakeProbe(level=lambda tpl, now: 5.0))
    assert len(opened(events)) == 2  # bursts are recurrences for dedup to judge, not a continuing regression


def test_short_incident_does_not_reopen():
    level = lambda tpl, now: 500.0 if now >= at(30) else 5.0  # noqa: E731
    _, events = run([sig("log_burst", "Redis failure", 10, 12)], 60, FakeProbe(level=level))
    assert "reopened" not in [e.kind for e in events]


def test_symptom_only_incidents_do_not_chain():
    bursts = [sig("log_burst", REST, i, i + 1) for i in (0, 6, 12, 18)]
    _, events = run(bursts, 40)
    assert len(opened(events)) >= 3


def test_cause_reclaims_recent_symptoms_from_weaker_incident():
    book, events = run([sig("log_burst", "Twitter integration error (x)", 0, 20),
                        sig("log_burst", REST, 10, 15, value=400_000),
                        sig("log_burst", "Topology is closed", 11, 14, new_template=True)], 40)
    db = next(i for i in book.incidents if i.component == "database")
    twitter = next(i for i in book.incidents if i.component == "external")
    assert any(s.label == REST for s in db.signals.values())
    assert not any(s.label == REST for s in twitter.signals.values())


def test_familiar_blip_cause_does_not_reclaim_symptoms():
    book, _ = run([sig("rps_shift", "RPS", 0, 10, value=110_000, base=80_000, key="rps"),
                   sig("log_burst", REST, 8, 14, value=20_000),
                   sig("log_burst", "Timeout <N> wait exceeded", 9, 9, value=3500, new_template=False)], 30)
    capacity = next(i for i in book.incidents if i.component == "capacity")
    assert any(s.label == REST for s in capacity.signals.values())
