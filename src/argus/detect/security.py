"""Signs of malicious automation in an incident window.

A rotating proxy pool shows up as one ISP that is normally invisible suddenly sending a large share
of the failing requests, each from a different IP. Mobile carriers rotate IPs too (CGNAT, IPv6), so
the share jump against the previous 24 hours is what separates a botnet from a busy carrier.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..timeutil import sql_ts


@dataclass
class BotFeatures:
    top_isp: str | None
    top_share: float      # share of the window's requests (with a known ISP) from the top ISP
    top_rotation: float   # distinct IPs / requests for that ISP
    prior_share: float    # the same ISP's share over the previous 24 hours
    anon_share: float     # requests without user_id
    requests: int


@dataclass
class BotCfg:
    min_share: float = 0.3
    min_rotation: float = 0.8
    max_prior_share: float = 0.05
    min_requests: int = 1000


def is_bot_like(f: BotFeatures, cfg: BotCfg | None = None) -> tuple[bool, str]:
    cfg = cfg or BotCfg()
    hit = (f.requests >= cfg.min_requests and f.top_share >= cfg.min_share
           and f.top_rotation >= cfg.min_rotation and f.prior_share <= cfg.max_prior_share)
    reason = (f"{f.top_isp}: {f.top_share:.0%} запросов окна, новый IP на {f.top_rotation:.0%} запросов, "
              f"за прошлые сутки доля {f.prior_share:.1%}")
    return hit, reason


def bot_features(store, start: datetime, end: datetime, tpl_ids: list[str] | None = None) -> BotFeatures:
    tpl_filter = ""
    if tpl_ids:
        tpl_filter = "AND tpl_id IN (" + ",".join(f"'{t}'" for t in tpl_ids if t.isalnum()) + ")"
    window = f"ts >= {sql_ts(start)} AND ts < {sql_ts(end)} {tpl_filter}"
    total, anon = store.con.execute(
        f"SELECT count(*), coalesce(avg((user_id IS NULL)::INT), 0) FROM logs WHERE {window} AND isp IS NOT NULL"
    ).fetchone()
    if not total:
        return BotFeatures(None, 0.0, 0.0, 0.0, 0.0, 0)
    isp, n, ips = store.con.execute(
        f"SELECT isp, count(*) n, count(DISTINCT ip) FROM logs WHERE {window} AND isp IS NOT NULL "
        "GROUP BY isp ORDER BY n DESC LIMIT 1").fetchone()
    prior_start = start - timedelta(hours=24)
    prior_total, prior_n = store.con.execute(
        f"SELECT count(*), count(*) FILTER (WHERE isp = $1) FROM logs "
        f"WHERE ts >= {sql_ts(prior_start)} AND ts < {sql_ts(start)} AND isp IS NOT NULL", [isp]).fetchone()
    return BotFeatures(isp, n / total, ips / n, (prior_n / prior_total) if prior_total else 0.0,
                       float(anon), int(total))
