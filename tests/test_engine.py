import json
from datetime import timedelta

from conftest import T0, log_line

from argus.config import load_config
from argus.engine import build_engine, replay
from argus.ingest import ingest

DAY = 144


def burst_dataset(dataset, tmp_path):
    quiet = [log_line(T0 + timedelta(minutes=10 * i, seconds=5), "Redis failure", user_id=str(i % 7))
             for i in range(3 * DAY)]
    start = T0 + timedelta(days=2, hours=3)  # 08-26 14:10
    burst = [log_line(start + timedelta(seconds=2 * i), "LOADING Valkey is loading the dataset in memory",
                      ip=f"10.3.{i // 200}.{i % 200}") for i in range(1500)]
    data = dataset(logs=quiet + burst, points=3 * DAY)
    ingest(data, tmp_path / "var")
    return load_config(None, data_dir=data, var_dir=tmp_path / "var", out_dir=tmp_path / "out"), start


def test_lifecycle_open_update_resolve(dataset, tmp_path):
    cfg, start = burst_dataset(dataset, tmp_path)
    stats = replay(build_engine(cfg, llm="off"))
    tasks = list((tmp_path / "out" / "tasks").glob("ARG-*.md"))
    assert len(tasks) == 1 and stats.opened == 1
    text = tasks[0].read_text()
    assert "assignee: DBA" in text and "## Симптомы" in text and "status: resolved" in text
    log = json.loads((tmp_path / "out" / "slack-log.json").read_text())
    root = log[0]
    assert root["payload"]["channel"] == "#app-alerts" and "thread_ts" not in root["payload"]
    assert any(e["payload"].get("thread_ts") == root["ts"] for e in log[1:])  # resolution posted in the thread
    assert any(e["method"] == "chat.update" for e in log)                     # root message marked resolved
    assert len(list((tmp_path / "out" / "postmortems").glob("ARG-*.md"))) == 1


def test_rerun_is_idempotent(dataset, tmp_path):
    cfg, _ = burst_dataset(dataset, tmp_path)
    replay(build_engine(cfg, llm="off"))
    before = (tmp_path / "out" / "slack-log.json").read_text()
    stats = replay(build_engine(cfg, llm="off"))
    assert stats.ticks == 0 and (tmp_path / "out" / "slack-log.json").read_text() == before
    assert len(list((tmp_path / "out" / "tasks").glob("ARG-*.md"))) == 1


def test_replay_has_no_lookahead(dataset, tmp_path):
    cfg, start = burst_dataset(dataset, tmp_path)
    engine = build_engine(cfg, llm="off")
    replay(engine)
    [record] = engine.memory.tasks.values()
    opened_at, opened_lines = record.opened_at, record.opened_lines
    seen_before = sum(1 for i in range(1500) if start + timedelta(seconds=2 * i) < opened_at)
    assert opened_lines == seen_before < 1500  # numbers at alert time come only from data before it
