"""Bursts of log templates.

A bucket is flagged when the count is far above the causal baseline in three senses at once:
robust z (Poisson noise + MAD + 10 % of the level), an absolute floor and a ratio. The first hours
are a warm-up: hourly cron-like bursts look anomalous until a day of history exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import numpy as np
import pandas as pd

from ..model import Point, Signal
from ..timeutil import BUCKET
from .baseline import regular, robust_scale, seasonal_baseline, segment


@dataclass
class LogCfg:
    z: float = 6.0
    min_count: float = 30
    min_ratio: float = 3.0
    rel_noise: float = 0.1
    warmup_buckets: int = 36
    min_len: int = 1
    max_gap: int = 2


def log_bursts(counts: pd.DataFrame, labels: dict[str, str], cfg: LogCfg | None = None) -> list[Signal]:
    """counts: regular 10-min grid × template id (0 = no lines)."""
    cfg = cfg or LogCfg()
    if counts.empty:
        return []
    warm = counts.index[0] + cfg.warmup_buckets * BUCKET
    signals: list[Signal] = []
    for key in counts.columns:
        s = counts[key]
        if s.max() < cfg.min_count:
            continue
        base = seasonal_baseline(s).fillna(0.0)
        scale = robust_scale(s - base).fillna(0.0)
        sigma = np.maximum(np.sqrt(base + 1.0), scale) + cfg.rel_noise * base
        z = (s - base) / sigma
        flags = (z >= cfg.z) & (s >= cfg.min_count) & (s >= cfg.min_ratio * (base + 1.0)) & (s.index >= warm)
        for ep in segment(flags, cfg.min_len, cfg.max_gap):
            window = s[ep.start:ep.end]
            peak_at = window[flags[ep.start:ep.end]].idxmax()
            before = s[s.index < ep.start]
            points = [Point(t.to_pydatetime(), float(s[t]), float(base[t]), float(z[t]), bool(flags[t]))
                      for t in window.index]
            signals.append(Signal(
                kind="log_burst", key=str(key), label=labels.get(key, str(key)),
                start=ep.start, end=ep.end, detected_at=ep.detected_at, peak_at=peak_at.to_pydatetime(),
                value=float(s[peak_at]), baseline=float(base[peak_at]), score=float(z[peak_at]),
                total=float(window.sum()), attrs={"new_template": bool(before.sum() == 0)}, points=points))
    return signals


def template_counts(store, start: datetime, end: datetime) -> pd.DataFrame:
    agg = store.df("SELECT bucket, tpl_id, n FROM agg_tpl_10m")
    if agg.empty:
        return pd.DataFrame()
    wide = agg.pivot(index="bucket", columns="tpl_id", values="n")
    return wide.apply(lambda col: regular(col, start, end, fill=0.0)).astype(float)


def detect_log_bursts(store, start: datetime, end: datetime, cfg: LogCfg | None = None) -> list[Signal]:
    labels = dict(store.df("SELECT tpl_id, tpl FROM templates").itertuples(index=False, name=None))
    return log_bursts(template_counts(store, start, end), labels, cfg)
