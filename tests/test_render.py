import json
from datetime import datetime, timedelta

import yaml

from argus.correlate import Impact, Incident
from argus.model import Point, Signal
from argus.render.fmt import human, pct
from argus.render.slack import SlackLog, alert_payload
from argus.render.task import render_postmortem, render_task
from argus.routing import Router
from argus.tracker import Tracker
from argus.triage import Hypothesis, Triage, fallback_triage

T = datetime(2026, 9, 2, 11, 20)


def incident() -> Incident:
    pts = [Point(T + timedelta(minutes=10 * i), 400_000, 5, 900, True) for i in range(3)]
    s = Signal("log_burst", "26fd977a0a", "LOADING Valkey is loading the dataset in memory", T, T + timedelta(minutes=20),
               T, T, 400_000, 5, 900, 1_200_000, {"new_template": True}, pts)
    inc = Incident("cache-x", "ops", "cache", "DBA", "data_store", T, T + timedelta(minutes=20), T, {"k": s},
                   status="open", detected_at=T + timedelta(minutes=10), severity="SEV-1", reason="high impact",
                   impact=Impact(lines=1_500_000, n5xx=1_400_000, clients=8_561_654, users=120_345, hosts=118,
                                 hosts_total=150, top_countries=[("IN", 4_000_000), ("US", 900_000)],
                                 requests=1.2e9, error_rate=0.012, peak_error_rate=0.0401))
    inc.task_id = "ARG-007"
    return inc


def triage() -> Triage:
    return Triage(title="Valkey недоступен: LOADING и шторм таймаутов REST", summary="Кластер кэша перезапустился.",
                  symptoms=["LOADING Valkey: 1,2 млн строк за 30 минут"],
                  hypotheses=[Hypothesis("Рестарт узла Valkey", "LOADING с 11:20", "высокая")],
                  assignee="DBA", assignee_reason="Ошибки кэша появились раньше таймаутов", next_steps=["Проверить узлы"],
                  source="claude", model="claude-sonnet-5-5", votes={"rules": "DBA", "analyst": "DBA", "arbiter": "DBA"})


def test_number_formatting():
    assert human(8_561_654) == "8,56 млн" and human(17_472) == "17,5 тыс." and human(950) == "950"
    assert pct(0.0401) == "4,0 %" and pct(0.0005) == "0,05 %"


def test_task_has_required_fields():
    md = render_task(incident(), triage(), history=[(T + timedelta(minutes=10), "открыт")])
    front = yaml.safe_load(md.split("---")[1])
    assert (front["id"], front["assignee"], front["severity"]) == ("ARG-007", "DBA", "SEV-1")
    for part in ("Valkey недоступен", "## Симптомы", "## Возможные причины", "## Затронутые пользователи",
                 "8,56 млн", "**Исполнитель:** DBA", "Рестарт узла Valkey"):
        assert part in md


def test_postmortem_has_sections():
    md = render_postmortem(incident(), triage(), history=[(T + timedelta(minutes=10), "открыт")])
    for part in ("# Post-mortem: ARG-007", "## Влияние", "## Хронология", "## Первопричина", "## Action items"):
        assert part in md


def test_slack_payload_is_valid_block_kit():
    payload = alert_payload(incident(), triage(), channel="#app-alerts", task_url="https://tracker.example.com/ARG-007")
    json.dumps(payload)
    assert payload["channel"] == "#app-alerts" and payload["text"]
    assert payload["blocks"][0]["type"] == "header" and len(payload["blocks"][0]["text"]["text"]) <= 150
    assert all(len(b.get("text", {}).get("text", "")) <= 3000 for b in payload["blocks"])


def test_repeat_replies_in_thread(tmp_path):
    log = SlackLog(tmp_path / "slack-log.json")
    root = log.post({"channel": "#app-alerts", "text": "a"}, at=T, meta={"event": "opened"})
    reply = log.reply(root, {"channel": "#app-alerts", "text": "b"}, at=T + timedelta(minutes=10), meta={})
    entries = json.loads((tmp_path / "slack-log.json").read_text())
    assert entries[1]["payload"]["thread_ts"] == root and float(reply) > float(root)


def test_tracker_assigns_ids_and_reads_front_matter(tmp_path):
    tracker = Tracker(tmp_path)
    a = tracker.create(incident(), triage(), history=[])
    b = tracker.create(incident(), triage(), history=[])
    assert (a.id, b.id) == ("ARG-001", "ARG-002") and a.path.exists()
    assert [t["id"] for t in tracker.list()] == ["ARG-001", "ARG-002"]


def test_fallback_triage_is_complete():
    t = fallback_triage(incident(), Router.load())
    assert t.assignee == "DBA" and t.title and t.hypotheses and t.symptoms and t.next_steps
    assert t.source == "rules"
