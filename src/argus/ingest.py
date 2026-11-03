"""Raw export → one DuckDB file (`var/argus.duckdb`, schema `raw`).

logs.json (NDJSON, ~16 GB) is read by DuckDB in parallel, templated with SQL masks and sorted by time,
so later time-window queries prune by zone maps. CSV metrics become long tables; `undefined`
(Prometheus topk gaps) is dropped, never turned into 0.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import duckdb
import pandas as pd

from .templates import sql_template_expr

TOPK_COLUMN_PREFIX = "topk("  # rps-by-country has one series without a country label
UNKNOWN_COUNTRY = "ZZ"

LOG_COLUMNS = {c: "VARCHAR" for c in (
    "request_ip", "response_code", "user_id", "application_client", "source", "message", "class", "timestamp")}


@dataclass
class IngestStats:
    log_rows: int
    templates: int
    rps_points: int
    t_min: object
    t_max: object
    seconds: float


def load_series_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, na_values=["undefined"])
    df.columns = ["ts", "value"]
    df["ts"] = pd.to_datetime(df["ts"], unit="ms")
    return df.dropna().reset_index(drop=True)


def load_wide_csv(path: Path, id_name: str) -> pd.DataFrame:
    df = pd.read_csv(path, na_values=["undefined"])
    df = df.rename(columns={df.columns[0]: "ts"})
    df = df.rename(columns={c: UNKNOWN_COUNTRY for c in df.columns if str(c).startswith(TOPK_COLUMN_PREFIX)})
    df["ts"] = pd.to_datetime(df["ts"], unit="ms")
    long = df.melt(id_vars="ts", var_name=id_name, value_name="value").dropna()
    return long.sort_values(["ts", id_name]).reset_index(drop=True)


def _logs_sql(src: Path) -> str:
    columns = "{" + ", ".join(f"'{k}': '{v}'" for k, v in LOG_COLUMNS.items()) + "}"
    tpl = sql_template_expr("message")
    return f"""
    CREATE OR REPLACE TABLE raw.logs AS
    WITH src AS (
        SELECT TRY_CAST("timestamp" AS TIMESTAMP) AS ts,
               request_ip AS ip,
               TRY_CAST(split_part(response_code, ' ', 1) AS INTEGER) AS status,
               user_id,
               json_extract_string(application_client, '$.country_code') AS country,
               json_extract_string(application_client, '$.region_code') AS region,
               json_extract_string(application_client, '$.city_name') AS city,
               json_extract_string(application_client, '$.isp_name') AS isp,
               "source" AS host,
               "class" AS cls,
               left(message, 2000) AS message,
               {tpl} AS tpl
        FROM read_json('{src}', format = 'newline_delimited', maximum_object_size = 1048576,
                       columns = {columns})
    )
    SELECT *, left(md5(tpl), 10) AS tpl_id FROM src WHERE ts IS NOT NULL ORDER BY ts
    """


AGG_SQL = [
    """CREATE OR REPLACE TABLE raw.templates AS
       SELECT tpl_id, any_value(tpl) AS tpl, mode(cls) AS cls, min(ts) AS first_ts, count(*) AS n,
              any_value(message) AS sample
       FROM raw.logs GROUP BY tpl_id""",
    """CREATE OR REPLACE TABLE raw.agg_tpl_10m AS
       SELECT time_bucket(INTERVAL 10 MINUTE, ts) + INTERVAL 10 MINUTE AS bucket, tpl_id,
              count(*) AS n, count(DISTINCT user_id) AS users,
              count(DISTINCT coalesce(user_id, ip)) AS clients, count(DISTINCT ip) AS ips,
              count(DISTINCT host) AS hosts, count(*) FILTER (WHERE status >= 500) AS n5xx
       FROM raw.logs GROUP BY ALL ORDER BY bucket, tpl_id""",
    """CREATE OR REPLACE TABLE raw.agg_logs_10m AS
       SELECT time_bucket(INTERVAL 10 MINUTE, ts) + INTERVAL 10 MINUTE AS bucket,
              count(*) AS n, count(DISTINCT user_id) AS users,
              count(DISTINCT coalesce(user_id, ip)) AS clients, count(DISTINCT ip) AS ips,
              count(DISTINCT host) AS hosts, count(*) FILTER (WHERE status >= 500) AS n5xx
       FROM raw.logs GROUP BY ALL ORDER BY bucket""",
]


def ingest(data_dir: Path, var_dir: Path) -> IngestStats:
    started = time.monotonic()
    data_dir, var_dir = Path(data_dir).resolve(), Path(var_dir).resolve()
    var_dir.mkdir(parents=True, exist_ok=True)
    db_path = var_dir / "argus.duckdb"
    tmp_path = var_dir / "argus.duckdb.tmp"
    tmp_path.unlink(missing_ok=True)

    con = duckdb.connect(str(tmp_path))
    con.execute(f"SET temp_directory = '{var_dir / 'duckdb_tmp'}'")
    con.execute("CREATE SCHEMA raw")
    con.execute(_logs_sql(data_dir / "logs.json"))
    for sql in AGG_SQL:
        con.execute(sql)

    rps = load_series_csv(data_dir / "rps.csv")
    cpu = load_series_csv(data_dir / "cpu-usage.csv")
    cpu["value"] = cpu["value"] * 100.0  # export is a fraction; we store percent
    countries = load_wide_csv(data_dir / "rps-by-country.csv", "country")
    endpoints = load_wide_csv(data_dir / "endpoint-timings-ms.csv", "endpoint")
    for name, frame in (("metric_rps", rps), ("metric_cpu", cpu), ("metric_country", countries),
                        ("metric_endpoint", endpoints)):
        con.register("frame", frame)
        con.execute(f"CREATE TABLE raw.{name} AS SELECT * FROM frame ORDER BY ts")
        con.unregister("frame")

    log_rows, t_min, t_max = con.execute("SELECT count(*), min(ts), max(ts) FROM raw.logs").fetchone()
    templates = con.execute("SELECT count(*) FROM raw.templates").fetchone()[0]
    con.execute("CREATE TABLE raw.meta AS SELECT ? AS data_dir, now() AS ingested_at", [str(data_dir)])
    con.close()
    tmp_path.replace(db_path)
    return IngestStats(log_rows, templates, len(rps), t_min, t_max, round(time.monotonic() - started, 1))
