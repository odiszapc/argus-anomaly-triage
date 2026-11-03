---
name: add-data-source
description: Use when Argus should read live data (Prometheus, Loki, ClickHouse, Elasticsearch) instead of the file export, or when the export format changes.
---

# Add a data source

Everything downstream reads the `raw.*` tables in `var/argus.duckdb` through the guarded views in
`store.py`. A new source only has to fill the same tables:

| table | columns |
|---|---|
| `raw.logs` | ts, ip, status INT, user_id, country, region, city, isp, host, cls, message, tpl, tpl_id |
| `raw.agg_tpl_10m` / `raw.agg_logs_10m` | 10-minute aggregates, bucket = window END |
| `raw.metric_rps`, `raw.metric_cpu` | ts, value (CPU in percent) |
| `raw.metric_country`, `raw.metric_endpoint` | ts, country/endpoint, value; missing points are absent rows |

1. Write `src/argus/sources/<name>.py` with a function that appends new rows since the last ingested
   timestamp (Prometheus: `query_range` with `step=600`; Loki/ClickHouse: SQL over the time range).
2. Template messages with `templates.sql_template_expr` (DuckDB) or `templates.template_of` (Python) so
   template ids stay stable across sources.
3. Rebuild the aggregates for the touched buckets only.
4. Test with a recorded response (no network in tests), then run `argus watch` against staging.
