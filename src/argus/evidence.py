"""The evidence pack: what code knows about an incident at `now`, compact enough (≤10 KB) for any model.

Everything here is computed, not generated, and the numbers in it are the ones the verifier accepts.
`blind=True` drops the routing layer's opinion so the arbiter judges the facts on its own.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .correlate import Incident
from .routing import Router
from .store import Store
from .timeutil import BUCKET, fmt, sql_ts


def _r(x: float | None, nd: int = 1):
    return None if x is None else round(float(x), nd)


def _metrics(store: Store, start: datetime, end: datetime) -> dict:
    day = timedelta(days=1)
    out: dict = {}
    for name, table, agg in (("rps", "metric_rps", "avg"), ("cpu_pct", "metric_cpu", "max")):
        now_v, prev_v = store.con.execute(
            f"SELECT (SELECT {agg}(value) FROM {table} WHERE ts > {sql_ts(start)} AND ts <= {sql_ts(end)}), "
            f"(SELECT {agg}(value) FROM {table} WHERE ts > {sql_ts(start - day)} AND ts <= {sql_ts(end - day)})"
        ).fetchone()
        out[name] = {"window": _r(now_v), "same_window_yesterday": _r(prev_v)}
    rows = store.con.execute(
        f"WITH w AS (SELECT endpoint, avg(value) v FROM metric_endpoint WHERE ts > {sql_ts(start - 2 * BUCKET)} "
        f"AND ts <= {sql_ts(end + 2 * BUCKET)} GROUP BY 1), "
        f"p AS (SELECT endpoint, avg(value) v FROM metric_endpoint WHERE ts > {sql_ts(start - day - 2 * BUCKET)} "
        f"AND ts <= {sql_ts(end - day + 2 * BUCKET)} GROUP BY 1) "
        "SELECT w.endpoint, w.v, p.v, w.v / p.v AS r FROM w JOIN p USING (endpoint) WHERE p.v > 0 "
        "ORDER BY r DESC LIMIT 5").fetchall()
    out["latency_ms_top_growth"] = [{"endpoint": e, "window": _r(a), "yesterday": _r(b), "ratio": _r(r, 2)}
                                    for e, a, b, r in rows]
    countries = store.con.execute(
        f"WITH w AS (SELECT country, avg(value) v FROM metric_country WHERE ts > {sql_ts(start)} "
        f"AND ts <= {sql_ts(end)} GROUP BY 1), p AS (SELECT country, avg(value) v FROM metric_country "
        f"WHERE ts > {sql_ts(start - day)} AND ts <= {sql_ts(end - day)} GROUP BY 1) "
        "SELECT w.country, w.v, p.v, w.v / p.v FROM w JOIN p USING (country) ORDER BY w.v DESC LIMIT 8").fetchall()
    out["countries_hits_per_s"] = [{"country": c, "window": _r(a), "yesterday": _r(b), "ratio": _r(r, 2)}
                                   for c, a, b, r in countries]
    return out


def _hosts(store: Store, incident: Incident, start: datetime, end: datetime) -> list[dict]:
    ids = ",".join(f"'{t}'" for t in incident.template_ids()[:10] if t.isalnum())
    if not ids:
        return []
    rows = store.con.execute(
        f"SELECT host, count(*) n FROM logs WHERE ts >= {sql_ts(start)} AND ts < {sql_ts(end)} AND tpl_id IN ({ids}) "
        "GROUP BY 1 ORDER BY n DESC LIMIT 5").fetchall()
    return [{"host": h, "lines": n} for h, n in rows]


def build_evidence(incident: Incident, store: Store, router: Router, now: datetime, blind: bool = False,
                   related: list[dict] | None = None) -> dict:
    start, end = incident.start - BUCKET, min(now, incident.end)
    signals = sorted(incident.signals.values(), key=lambda s: -s.total)[:10]
    comp = router.get(incident.component)
    imp = incident.impact
    pack: dict = {
        "incident": {"now": fmt(now), "first_anomalous_bucket_start": fmt(start),
                     "last_anomalous_bucket": fmt(incident.end),
                     "duration_min": int((end - start).total_seconds() // 60), "severity": incident.severity,
                     "why_alerted": incident.reason},
        "impact": {"error_lines": imp.lines, "lines_5xx": imp.n5xx, "clients": imp.clients,
                   "logged_in_users": imp.users, "hosts_with_errors": imp.hosts, "hosts_total": imp.hosts_total,
                   "peak_error_rate": _r(imp.peak_error_rate, 5), "window_error_rate": _r(imp.error_rate, 5),
                   "requests_in_window": _r(imp.requests, 0), "requests_delta": _r(imp.requests_delta, 0),
                   "top_countries_by_clients": [{"country": c, "clients": n} for c, n in imp.top_countries]},
        "signals": [{"kind": s.kind, "what": s.label[:160], "start": fmt(s.start - BUCKET), "end": fmt(s.end),
                     "peak_per_10min": _r(s.value, 0), "usual_per_10min": _r(s.baseline, 1),
                     "ratio": _r(s.value / s.baseline, 1) if s.baseline else None, "total": _r(s.total, 0),
                     "never_seen_before": bool(s.attrs.get("new_template")), **(
                         {"direction": s.attrs["direction"]} if "direction" in s.attrs else {})}
                    for s in signals],
        "metrics": _metrics(store, start, end),
        "hosts_top": _hosts(store, incident, start, end),
    }
    if incident.bot:
        b = incident.bot
        pack["traffic_source"] = {"top_isp": b.top_isp, "top_isp_share": _r(b.top_share, 3),
                                  "distinct_ips_per_request": _r(b.top_rotation, 3),
                                  "same_isp_share_prev_24h": _r(b.prior_share, 4),
                                  "anonymous_share": _r(b.anon_share, 3)}
    if not blind:
        pack["routing"] = {"component": comp.name, "component_title": comp.title, "rules_assignee": incident.role,
                           "typical_causes": comp.hypotheses}
        if related:
            pack["recent_tasks"] = related[:5]
    return pack
