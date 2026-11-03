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


if __name__ == "__main__":
    app()
