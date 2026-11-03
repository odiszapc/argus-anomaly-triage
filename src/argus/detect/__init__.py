"""All detectors behind one call. Every detector is causal, so running over the full history and
revealing signals by `detected_at` (replay) equals running at each tick (watch)."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any

from ..model import Signal
from ..timeutil import floor_bucket
from .countries import CountryCfg, detect_countries
from .logs import LogCfg, detect_log_bursts
from .metrics import MetricCfg, detect_metrics
from .security import BotCfg


def _build(cls, values: dict[str, Any] | None):
    allowed = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in (values or {}).items() if k in allowed})


@dataclass
class DetectCfg:
    logs: LogCfg = field(default_factory=LogCfg)
    metrics: MetricCfg = field(default_factory=MetricCfg)
    countries: CountryCfg = field(default_factory=CountryCfg)
    bots: BotCfg = field(default_factory=BotCfg)

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> DetectCfg:
        d = d or {}
        return cls(_build(LogCfg, d.get("logs")), _build(MetricCfg, d.get("metrics")),
                   _build(CountryCfg, d.get("countries")), _build(BotCfg, d.get("bots")))


def data_window(store) -> tuple[datetime, datetime]:
    """Grid [first metric point, last complete bucket at `now`]."""
    start, end = store.time_range()
    if store.now is not None:
        end = min(end, floor_bucket(store.now))
    return start, end


def detect_all(store, cfg: DetectCfg | None = None) -> list[Signal]:
    cfg = cfg or DetectCfg()
    start, end = data_window(store)
    signals = (detect_log_bursts(store, start, end, cfg.logs)
               + detect_metrics(store, start, end, cfg.metrics)
               + detect_countries(store, start, end, cfg.countries))
    return sorted(signals, key=lambda s: (s.detected_at, s.kind, s.key))
