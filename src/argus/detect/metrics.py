"""RPS, CPU and overall traffic.

RPS has a known defect: single-point doublings (and the odd halving) that neither CPU nor the
independent per-country hit counter confirms. Those points are `rps_artifact`: they never page,
they are removed before the seasonal baseline is computed (otherwise a scheduled artifact inflates
the same-time median and the next normal value looks like a drop), and correlation folds them into
one data-quality task.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import pandas as pd

from ..model import Point, Signal
from .baseline import regular, seasonal_baseline, segment


@dataclass
class MetricCfg:
    artifact_ratio: float = 0.5   # |rps / local median - 1|
    calm_band: float = 0.15       # cpu and country ratios inside ±15 % = "not confirmed"
    local_window: int = 12        # buckets for the local (trailing) median
    shift_ratio: float = 0.3      # corroborated |rps / seasonal - 1|
    cpu_high_pct: float = 85.0
    cpu_min_len: int = 2
    traffic_ratio: float = 0.25
    traffic_min_len: int = 3
    max_gap: int = 1


def _local_ratio(s: pd.Series, window: int) -> pd.Series:
    return s / s.shift(1).rolling(window, min_periods=3).median()


def episodes(kind: str, key: str, label: str, values: pd.Series, base: pd.Series, flags: pd.Series,
              min_len: int, max_gap: int, attrs: dict | None = None) -> list[Signal]:
    out = []
    ratio = values / base
    for ep in segment(flags.fillna(False).astype(bool), min_len, max_gap):
        window = values[ep.start:ep.end]
        dev = (ratio[ep.start:ep.end] - 1).abs()
        peak_at = dev.idxmax() if dev.notna().any() else window.index[0]
        points = [Point(t.to_pydatetime(), float(values[t]), float(base[t]), float(ratio[t]), bool(flags[t]))
                  for t in window.index]
        out.append(Signal(kind, key, label, ep.start, ep.end, ep.detected_at, peak_at.to_pydatetime(),
                          float(values[peak_at]), float(base[peak_at]), float(ratio[peak_at]),
                          float(window.sum()), dict(attrs or {}), points))
    return out


def rps_signals(rps: pd.Series, cpu: pd.Series, countries: pd.Series, cfg: MetricCfg | None = None) -> list[Signal]:
    cfg = cfg or MetricCfg()
    local = rps.shift(1).rolling(cfg.local_window, min_periods=3).median()
    calm = (((_local_ratio(cpu, cfg.local_window) - 1).abs() < cfg.calm_band)
            & ((_local_ratio(countries, cfg.local_window) - 1).abs() < cfg.calm_band))
    artifact = ((rps / local - 1).abs() >= cfg.artifact_ratio) & calm
    base = seasonal_baseline(rps.mask(artifact))
    corroborated = (((cpu / seasonal_baseline(cpu)) - 1).abs() >= cfg.calm_band) | \
                   (((countries / seasonal_baseline(countries)) - 1).abs() >= cfg.calm_band)
    shift = ((rps / base - 1).abs() >= cfg.shift_ratio) & ~artifact & corroborated
    return (episodes("rps_artifact", "rps", "RPS", rps, local, artifact, 1, 0,
                      {"note": "not confirmed by CPU or per-country hits"})
            + episodes("rps_shift", "rps", "RPS", rps, base, shift, 1, cfg.max_gap))


def cpu_signals(cpu: pd.Series, cfg: MetricCfg | None = None) -> list[Signal]:
    cfg = cfg or MetricCfg()
    base = seasonal_baseline(cpu)
    return episodes("cpu_high", "cpu", "CPU, %", cpu, base, cpu >= cfg.cpu_high_pct, cfg.cpu_min_len, cfg.max_gap)


def traffic_signals(countries: pd.Series, cfg: MetricCfg | None = None) -> list[Signal]:
    """Overall traffic (sum of per-country hits) vs the same time on previous days; no cold-start guess."""
    cfg = cfg or MetricCfg()
    base = seasonal_baseline(countries, fallback=0)
    flags = ((countries / base - 1).abs() >= cfg.traffic_ratio)
    return episodes("traffic_shift", "traffic", "Трафик (сумма по странам)", countries, base, flags,
                     cfg.traffic_min_len, cfg.max_gap)


def metric_series(store, start: datetime, end: datetime) -> tuple[pd.Series, pd.Series, pd.Series]:
    rps = store.df("SELECT ts, value FROM metric_rps").set_index("ts")["value"]
    cpu = store.df("SELECT ts, value FROM metric_cpu").set_index("ts")["value"]
    countries = store.df("SELECT ts, sum(value) AS value FROM metric_country GROUP BY ts").set_index("ts")["value"]
    return tuple(regular(s.astype(float), start, end) for s in (rps, cpu, countries))


def detect_metrics(store, start: datetime, end: datetime, cfg: MetricCfg | None = None) -> list[Signal]:
    rps, cpu, countries = metric_series(store, start, end)
    if rps.dropna().empty:
        return []
    return rps_signals(rps, cpu, countries, cfg) + cpu_signals(cpu, cfg) + traffic_signals(countries, cfg)

