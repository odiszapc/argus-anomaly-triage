"""SQL measurements behind the incident book: impact, current template level, bot features.

All queries go through the now-guarded views, so numbers at `now` never include later data.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .correlate import Impact, Incident
from .detect.security import BotFeatures, bot_features
from .store import Store
from .timeutil import BUCKET, BUCKET_S, sql_ts


def _in_list(ids: list[str]) -> str:
    return ",".join(f"'{i}'" for i in ids if i.isalnum())


class StoreProbe:
    def __init__(self, store: Store):
        self.store = store
        self._hosts_total: dict[str, int] = {}

    def window(self, incident: Incident, now: datetime) -> tuple[datetime, datetime]:
        """Log time range covered by the incident's buckets so far: [first label - 10m, last label)."""
        return incident.start - BUCKET, min(now, incident.end)

    def impact(self, incident: Incident, now: datetime) -> Impact:
        start, end = self.window(incident, now)
        impact = Impact()
        delta = [(p.value - p.baseline) * BUCKET_S for s in incident.signals.values()
                 if s.kind in ("country_shift", "rps_shift", "traffic_shift") for p in s.points
                 if p.flagged and p.baseline == p.baseline]
        impact.requests_delta = float(sum(delta))
        impact.requests = float(self.store.scalar(
            f"SELECT coalesce(sum(value), 0) * {BUCKET_S} FROM metric_rps "
            f"WHERE ts > {sql_ts(start)} AND ts <= {sql_ts(end)}") or 0.0)
        ids = _in_list(incident.template_ids())
        if not ids:
            return impact
        where = f"ts >= {sql_ts(start)} AND ts < {sql_ts(end)} AND tpl_id IN ({ids})"
        row = self.store.con.execute(
            f"SELECT count(*), count(*) FILTER (WHERE status >= 500), count(DISTINCT coalesce(user_id, ip)), "
            f"count(DISTINCT user_id), count(DISTINCT host) FROM logs WHERE {where}").fetchone()
        impact.lines, impact.n5xx, impact.clients, impact.users, impact.hosts = (int(v or 0) for v in row)
        impact.top_countries = [(c, int(n)) for c, n in self.store.con.execute(
            f"SELECT country, count(DISTINCT coalesce(user_id, ip)) AS n FROM logs "
            f"WHERE {where} AND country IS NOT NULL GROUP BY 1 ORDER BY n DESC, 1 LIMIT 5").fetchall()]
        impact.hosts_total = self._hosts(end)
        impact.error_rate = impact.n5xx / impact.requests if impact.requests else 0.0
        impact.peak_error_rate = float(self.store.scalar(
            f"SELECT coalesce(max(e.n5xx / (r.value * {BUCKET_S})), 0) FROM "
            f"(SELECT bucket, sum(n5xx) AS n5xx FROM agg_tpl_10m WHERE tpl_id IN ({ids}) "
            f"AND bucket > {sql_ts(start)} AND bucket <= {sql_ts(end)} GROUP BY bucket) e "
            f"JOIN metric_rps r ON r.ts = e.bucket WHERE r.value > 0") or 0.0)
        return impact

    def _hosts(self, end: datetime) -> int:
        day = end.strftime("%Y-%m-%d")
        if day not in self._hosts_total:
            self._hosts_total[day] = int(self.store.scalar(
                f"SELECT count(DISTINCT host) FROM logs WHERE ts >= {sql_ts(end - timedelta(hours=24))} "
                f"AND ts < {sql_ts(end)}") or 0)
        return self._hosts_total[day]

    def _median_count(self, tpl_id: str, start: datetime, end: datetime) -> float:
        """Median count per bucket over labels (start, end], empty buckets counted as 0."""
        if not tpl_id.isalnum():
            return 0.0
        return float(self.store.scalar(
            f"WITH grid AS (SELECT unnest(generate_series({sql_ts(start + BUCKET)}, {sql_ts(end)}, "
            f"INTERVAL 10 MINUTE)) AS bucket) "
            f"SELECT coalesce(median(coalesce(a.n, 0)), 0) FROM grid LEFT JOIN agg_tpl_10m a "
            f"ON a.bucket = grid.bucket AND a.tpl_id = '{tpl_id}'") or 0.0)

    def level(self, tpl_id: str, now: datetime) -> float:
        """Median over the last hour: steady level, blind to a single cron burst."""
        return self._median_count(tpl_id, now - 6 * BUCKET, now)

    def typical(self, tpl_id: str, before: datetime) -> float:
        """Median per bucket over the 24 hours before `before`."""
        return self._median_count(tpl_id, before - timedelta(hours=24), before)

    def bot(self, incident: Incident, now: datetime) -> BotFeatures | None:
        ids = incident.template_ids()[:10]
        if not ids:
            return None
        start, end = self.window(incident, now)
        return bot_features(self.store, start, end, ids)
