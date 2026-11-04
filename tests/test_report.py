from datetime import timedelta

from conftest import T0, log_line
from typer.testing import CliRunner

from argus.cli import app
from argus.config import load_config
from argus.engine import build_engine, replay
from argus.ingest import ingest
from argus.report import build_report

DAY = 144


def tiny_run(dataset, tmp_path):
    """Three quiet days with one Valkey burst: one task, ARG-001 (same shape as tests/test_engine.py)."""
    quiet = [log_line(T0 + timedelta(minutes=10 * i, seconds=5), "Redis failure", user_id=str(i % 7))
             for i in range(3 * DAY)]
    start = T0 + timedelta(days=2, hours=3)
    burst = [log_line(start + timedelta(seconds=2 * i), "LOADING Valkey is loading the dataset in memory",
                      ip=f"10.3.{i // 200}.{i % 200}") for i in range(1500)]
    data = dataset(logs=quiet + burst, points=3 * DAY)
    ingest(data, tmp_path / "var")
    cfg = load_config(None, data_dir=data, var_dir=tmp_path / "var", out_dir=tmp_path / "out")
    replay(build_engine(cfg, llm="off"))
    return cfg


def test_report_has_tasks_period_and_links(dataset, tmp_path):
    cfg = tiny_run(dataset, tmp_path)
    page = build_report(cfg)
    end = T0 + timedelta(minutes=10 * (3 * DAY - 1))
    assert "ARG-001" in page
    assert f"{T0:%Y-%m-%d %H:%M} → {end:%Y-%m-%d %H:%M} UTC" in page
    assert 'href="tasks/ARG-001-' in page and 'href="postmortems/ARG-001-' in page
    assert 'src="http' not in page and "<link" not in page  # opens from disk, nothing fetched

    res = CliRunner().invoke(app, ["report", "--out", str(cfg.paths.out_dir)],
                             env={"ARGUS_VAR_DIR": str(cfg.paths.var_dir)})
    assert res.exit_code == 0, res.output
    path = cfg.paths.out_dir / "report.html"
    assert str(path) in res.output and "ARG-001" in path.read_text(encoding="utf-8")


def test_report_shows_paths_relative_to_its_folder(dataset, tmp_path):
    cfg = tiny_run(dataset, tmp_path)
    page = build_report(cfg)
    assert str(tmp_path) not in page  # the page gets shared; the author's local directories stay local
    assert "состояние: .argus/state.pkl · данные: ../var/argus.duckdb" in page


def test_report_without_a_run_is_a_clear_error(tmp_path):
    res = CliRunner().invoke(app, ["report", "--out", str(tmp_path / "nothing")])
    assert res.exit_code != 0 and "argus replay" in res.output
