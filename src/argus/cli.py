"""Command line: `argus <command>`. Every command reads config/argus.yaml unless --config is given."""

from __future__ import annotations

from pathlib import Path

import typer

from .config import load_config

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Argus: anomalies in metrics and logs → triage tasks, Slack alerts, post-mortems.")

ConfigOpt = typer.Option(None, "--config", "-c", help="Path to argus.yaml")


@app.callback()
def main() -> None:
    """Keeps Typer in multi-command mode."""


@app.command()
def ingest(data: Path = typer.Option(None, help="Folder with logs.json and the CSV exports"),
           var: Path = typer.Option(None, help="Working folder for argus.duckdb"),
           config: Path = ConfigOpt) -> None:
    """Load the raw export into var/argus.duckdb (logs are templated and sorted by time)."""
    from .ingest import ingest as run_ingest

    cfg = load_config(config, data_dir=data, var_dir=var)
    typer.echo(f"ingest {cfg.paths.data_dir} → {cfg.paths.db}")
    stats = run_ingest(cfg.paths.data_dir, cfg.paths.var_dir)
    typer.echo(f"logs: {stats.log_rows:,} rows, {stats.templates} templates, {stats.t_min} … {stats.t_max}")
    typer.echo(f"metrics: {stats.rps_points} rps points; took {stats.seconds}s")



LlmOpt = typer.Option(None, "--llm", help="auto | claude | local | off (default from config / ARGUS_LLM)")
OutOpt = typer.Option(None, "--out", help="Where tasks/, postmortems/ and slack-log.json are written")


def _summary(engine, stats) -> None:
    typer.echo(f"ticks {stats.ticks} · opened {stats.opened} · repeats {stats.repeats} · resolved {stats.resolved} "
               f"· blips {stats.blips} · predictions {stats.predictions} · {stats.seconds}s")
    for r in engine.memory.tasks.values():
        inc = engine.incident(r.incident_uid)
        rep = f" (+{len(r.repeats)} повт.)" if r.repeats else ""
        typer.echo(f"  {r.task_id} {r.severity} {r.triage.assignee:15} {inc.start:%m-%d %H:%M} "
                   f"{r.triage.title[:80]}{rep}")


def _parse(ts: str | None):
    from .timeutil import parse_ts
    return parse_ts(ts) if ts else None


@app.command()
def replay(since: str = typer.Option(None, help="Start (UTC), default: start of data"),
           until: str = typer.Option(None, help="End (UTC), default: end of data"),
           llm: str = LlmOpt, fresh: bool = typer.Option(False, help="Drop state and generated outputs first"),
           out: Path = OutOpt, config: Path = ConfigOpt) -> None:
    """Replay history as if live: 10-minute ticks, every decision uses only data before `now`."""
    from .engine import build_engine, reset_outputs
    from .engine import replay as run_replay

    cfg = load_config(config, out_dir=out)
    if fresh:
        reset_outputs(cfg)
    engine = build_engine(cfg, llm)
    _summary(engine, run_replay(engine, _parse(since), _parse(until)))


@app.command()
def run(until: str = typer.Option(None, help="Process up to this time (UTC), default: latest data"),
        llm: str = LlmOpt, out: Path = OutOpt, config: Path = ConfigOpt) -> None:
    """One pass from the saved cursor to the latest data (for cron / Kubernetes CronJob)."""
    from .engine import build_engine
    from .engine import replay as run_replay

    cfg = load_config(config, out_dir=out)
    engine = build_engine(cfg, llm)
    _summary(engine, run_replay(engine, until=_parse(until)))


@app.command()
def watch(interval: int = typer.Option(300, help="Seconds between passes"), llm: str = LlmOpt, out: Path = OutOpt,
          config: Path = ConfigOpt) -> None:
    """Resident mode: a pass every --interval seconds (state survives restarts)."""
    import time

    from .engine import build_engine
    from .engine import replay as run_replay

    cfg = load_config(config, out_dir=out)
    while True:
        engine = build_engine(cfg, llm)
        stats = run_replay(engine)
        if stats.ticks:
            _summary(engine, stats)
        engine.store.close()
        time.sleep(interval)



@app.command("eval")
def eval_(out: Path = OutOpt, write: Path = typer.Option(None, help="Also write the markdown table here"),
          config: Path = ConfigOpt) -> None:
    """Score the last run against evals/gold.yaml: recall, assignee, time to detect, repeats, predictions."""
    import pickle

    from .evals import detections_from, evaluate, load_gold, render

    cfg = load_config(config, out_dir=out)
    state = cfg.paths.out_dir / ".argus" / "state.pkl"
    if not state.exists():
        raise typer.BadParameter(f"no run state at {state}; run `argus replay` first")
    memory = pickle.loads(state.read_bytes())
    result = evaluate(load_gold(cfg.paths.gold), detections_from(memory), memory.predictions)
    text = render(result)
    typer.echo(text)
    if write:
        Path(write).write_text(text + "\n")



@app.command()
def mcp(config: Path = ConfigOpt, out: Path = OutOpt) -> None:
    """MCP server (stdio) with read-only SQL and the task tracker, for Claude Code and other agents."""
    from .mcp_server import build_server

    build_server(load_config(config, out_dir=out)).run()


@app.command()
def sql(query: str, config: Path = ConfigOpt) -> None:
    """Run one read-only query against the data (the analyst's tool, from the shell)."""
    from .llm.tools import run_sql
    from .store import Store

    typer.echo(run_sql(Store(load_config(config).paths.db), query, max_rows=200, timeout_s=120))


@app.command()
def report(out: Path = OutOpt, config: Path = ConfigOpt) -> None:
    """One self-contained HTML page about a run (scores, timeline, tasks, eval, predictions) → <out>/report.html."""
    from .report import build_report

    cfg = load_config(config, out_dir=out)
    try:
        page = build_report(cfg)
    except FileNotFoundError as e:
        raise typer.BadParameter(str(e)) from None
    path = cfg.paths.out_dir / "report.html"
    path.write_text(page, encoding="utf-8")
    typer.echo(str(path))



@app.command()
def render(out: Path = OutOpt, config: Path = ConfigOpt) -> None:
    """Re-render tasks and post-mortems from the saved run state (after editing templates); no model calls."""
    from .engine import build_engine

    engine = build_engine(load_config(config, out_dir=out), llm="off")
    engine.rerender()
    typer.echo(f"re-rendered {len(engine.memory.tasks)} tasks")


if __name__ == "__main__":
    app()
