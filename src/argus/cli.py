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
        typer.echo(f"  {r.task_id} {inc.severity} {r.triage.assignee:15} {inc.start:%m-%d %H:%M} {r.triage.title[:80]}{rep}")


def _parse(ts: str | None):
    from .timeutil import parse_ts
    return parse_ts(ts) if ts else None


@app.command()
def replay(since: str = typer.Option(None, help="Start (UTC), default: start of data"),
           until: str = typer.Option(None, help="End (UTC), default: end of data"),
           llm: str = LlmOpt, fresh: bool = typer.Option(False, help="Drop state and generated outputs first"),
           out: Path = OutOpt, config: Path = ConfigOpt) -> None:
    """Replay history as if live: 10-minute ticks, every decision uses only data before `now`."""
    from .engine import build_engine, replay as run_replay, reset_outputs

    cfg = load_config(config, out_dir=out)
    if fresh:
        reset_outputs(cfg)
    engine = build_engine(cfg, llm)
    _summary(engine, run_replay(engine, _parse(since), _parse(until)))


@app.command()
def run(until: str = typer.Option(None, help="Process up to this time (UTC), default: latest data"),
        llm: str = LlmOpt, out: Path = OutOpt, config: Path = ConfigOpt) -> None:
    """One pass from the saved cursor to the latest data (for cron / Kubernetes CronJob)."""
    from .engine import build_engine, replay as run_replay

    cfg = load_config(config, out_dir=out)
    engine = build_engine(cfg, llm)
    _summary(engine, run_replay(engine, until=_parse(until)))


@app.command()
def watch(interval: int = typer.Option(300, help="Seconds between passes"), llm: str = LlmOpt, out: Path = OutOpt,
          config: Path = ConfigOpt) -> None:
    """Resident mode: a pass every --interval seconds (state survives restarts)."""
    import time

    from .engine import build_engine, replay as run_replay

    cfg = load_config(config, out_dir=out)
    while True:
        engine = build_engine(cfg, llm)
        stats = run_replay(engine)
        if stats.ticks:
            _summary(engine, stats)
        engine.store.close()
        time.sleep(interval)


if __name__ == "__main__":
    app()
