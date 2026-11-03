"""Read-only access to the ingested data with a moving `now`.

Every public view hides data that would not exist yet at `now` (logs with ts >= now, buckets and
metric points labelled after now). Detectors, impact queries and the LLM's SQL tool all read these
views, so replay over history cannot look ahead.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import duckdb
import pandas as pd

from .timeutil import sql_ts

FAR_FUTURE = datetime(2100, 1, 1)

VIEWS: dict[str, str] = {
    "logs": "SELECT * FROM raw.logs WHERE ts < getvariable('argus_now')",
    "templates": "SELECT tpl_id, tpl, cls, first_ts, sample FROM raw.templates "
                 "WHERE first_ts < getvariable('argus_now')",
    "agg_tpl_10m": "SELECT * FROM raw.agg_tpl_10m WHERE bucket <= getvariable('argus_now')",
    "agg_logs_10m": "SELECT * FROM raw.agg_logs_10m WHERE bucket <= getvariable('argus_now')",
    "metric_rps": "SELECT * FROM raw.metric_rps WHERE ts <= getvariable('argus_now')",
    "metric_cpu": "SELECT * FROM raw.metric_cpu WHERE ts <= getvariable('argus_now')",
    "metric_country": "SELECT * FROM raw.metric_country WHERE ts <= getvariable('argus_now')",
    "metric_endpoint": "SELECT * FROM raw.metric_endpoint WHERE ts <= getvariable('argus_now')",
}


class Store:
    def __init__(self, db_path: Path, now: datetime | None = None):
        self.db_path = Path(db_path)
        self.con = duckdb.connect(str(self.db_path), read_only=True,
                                  config={"enable_external_access": False})
        self.now: datetime | None = None
        self.set_now(now)
        for name, query in VIEWS.items():
            self.con.execute(f"CREATE OR REPLACE TEMP VIEW {name} AS {query}")

    def set_now(self, now: datetime | None) -> None:
        self.now = now
        self.con.execute(f"SET VARIABLE argus_now = {sql_ts(now or FAR_FUTURE)}")

    def df(self, query: str, params: list | None = None) -> pd.DataFrame:
        return self.con.execute(query, params or []).df()

    def scalar(self, query: str, params: list | None = None):
        row = self.con.execute(query, params or []).fetchone()
        return row[0] if row else None

    def time_range(self) -> tuple[datetime, datetime]:
        """Full data range, ignoring `now` (used to drive replay)."""
        return self.con.execute("SELECT min(ts), max(ts) FROM raw.metric_rps").fetchone()

    def close(self) -> None:
        self.con.close()
