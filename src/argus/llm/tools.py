"""The analyst's only tool: read-only SQL over the now-guarded views.

Guard rails, in code rather than in the prompt: one SELECT statement, whitelisted views only (so
`raw.*` and its future rows stay out of reach), no file access (the connection has external access
disabled), a row cap and a timeout. The same function backs the MCP server for human operators.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime

import duckdb

ALLOWED = {"logs", "templates", "agg_tpl_10m", "agg_logs_10m", "metric_rps", "metric_cpu", "metric_country",
           "metric_endpoint"}

SCHEMA_DOC = """\
Views (DuckDB SQL; times are naive UTC; every view only shows data that existed at alert time):
- logs(ts TIMESTAMP, ip, status INT, user_id, country, region, city, isp, host, cls, message, tpl, tpl_id)
  one row per error/warning log line; tpl = message with numbers/ids masked; ~35M rows over 14 days —
  always filter by ts and prefer the aggregates below.
- templates(tpl_id, tpl, cls, first_ts, sample)
- agg_tpl_10m(bucket TIMESTAMP, tpl_id, n, users, clients, ips, hosts, n5xx)  -- bucket = END of a 10-min window
- agg_logs_10m(bucket, n, users, clients, ips, hosts, n5xx)
- metric_rps(ts, value)                 -- requests/s, unsampled, 10-min step (ts = end of window)
- metric_cpu(ts, value)                 -- average CPU of app servers, percent
- metric_country(ts, country, value)    -- sampled hits/s per country; only top-10 countries per point
- metric_endpoint(ts, endpoint, value)  -- response time, ms, 30-min step, top endpoints only
"""


def _cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, float):
        return f"{v:.6g}"
    s = str(v).replace("\n", " ")
    return s if len(s) <= 160 else s[:159] + "…"


def _references(con, query: str) -> tuple[set[str], set[str]]:
    """Tables and table functions named in the query, from DuckDB's own parse tree (before views expand).
    Schema-qualified names come back as "schema.table" and never match the whitelist."""
    tree = json.loads(con.execute("SELECT json_serialize_sql(?)", [query]).fetchone()[0])
    if tree.get("error"):
        raise ValueError(tree.get("error_message", "cannot parse query"))
    tables: set[str] = set()
    functions: set[str] = set()
    ctes: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            if node.get("type") == "BASE_TABLE":
                prefix = ".".join(p for p in (node.get("catalog_name"), node.get("schema_name")) if p)
                name = str(node.get("table_name", "")).lower()
                tables.add(f"{prefix}.{name}" if prefix else name)
            elif node.get("type") == "TABLE_FUNCTION":
                functions.add(str(node.get("function", {}).get("function_name", "?")))
            for entry in (node.get("cte_map") or {}).get("map", []):
                ctes.add(str(entry.get("key", "")).lower())
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(tree)
    return tables - ctes, functions


def run_sql(store, query: str, max_rows: int = 50, timeout_s: float = 20.0) -> str:
    q = (query or "").strip().rstrip(";").strip()
    if not q:
        return "ERROR: empty query"
    try:
        statements = store.con.extract_statements(q)
    except duckdb.Error as e:
        return f"ERROR: {e}"
    if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
        return "ERROR: only a single SELECT (or WITH … SELECT) statement is allowed"
    try:
        tables, functions = _references(store.con, q)
    except (duckdb.Error, ValueError) as e:
        return f"ERROR: {e}"
    if functions:
        return f"ERROR: table functions are not allowed: {sorted(functions)}"
    bad = sorted(t for t in tables if t not in ALLOWED)
    if bad:
        return f"ERROR: unknown or forbidden tables {bad}; allowed: {sorted(ALLOWED)}"
    timer = threading.Timer(timeout_s, store.con.interrupt)
    timer.start()
    try:
        cur = store.con.execute(f"SELECT * FROM ({q}) AS _argus_q LIMIT {max_rows + 1}")
        rows = cur.fetchall()
        header = [d[0] for d in cur.description]
    except duckdb.Error as e:
        return f"ERROR: {str(e).splitlines()[0]}"
    finally:
        timer.cancel()
    lines = [",".join(header)] + [",".join(_cell(v) for v in row) for row in rows[:max_rows]]
    if len(rows) > max_rows:
        lines.append(f"… (обрезано до {max_rows} строк, добавьте агрегацию или LIMIT)")
    return "\n".join(lines)
