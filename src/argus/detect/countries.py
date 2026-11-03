"""Traffic shift in one country (SEO).

Each country is compared with its own same-time median of previous days; the "global" movement is
the median of all country ratios at that moment, so a shift that every country shares is not an SEO
signal. The export keeps only the top 10 countries per point: a missing value is "unknown", never 0.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import pandas as pd

from ..model import Signal
from .baseline import regular, seasonal_baseline
from .metrics import episodes


@dataclass
class CountryCfg:
    up: float = 1.5
    down: float = 0.65
    divergence: float = 0.3
    min_len: int = 12  # 2 h: shorter night-time wobbles of small countries are not an SEO matter
    max_gap: int = 3
    min_days: int = 2


def country_shifts(wide: pd.DataFrame, cfg: CountryCfg | None = None) -> list[Signal]:
    """wide: regular 10-min grid × country code, NaN where the country was not in the top-k."""
    cfg = cfg or CountryCfg()
    bases = wide.apply(lambda s: seasonal_baseline(s, min_days=cfg.min_days, fallback=0))
    ratios = wide / bases
    global_ratio = ratios.median(axis=1, skipna=True)
    signals: list[Signal] = []
    for country in wide.columns:
        r = ratios[country]
        for direction, flags in (("up", (r >= cfg.up) & (r - global_ratio >= cfg.divergence)),
                                 ("down", (r <= cfg.down) & (global_ratio - r >= cfg.divergence))):
            signals += episodes("country_shift", str(country), str(country), wide[country], bases[country],
                                 flags, cfg.min_len, cfg.max_gap, {"direction": direction})
    return signals


def detect_countries(store, start: datetime, end: datetime, cfg: CountryCfg | None = None) -> list[Signal]:
    long = store.df("SELECT ts, country, value FROM metric_country")
    if long.empty:
        return []
    wide = long.pivot(index="ts", columns="country", values="value")
    wide = wide.apply(lambda col: regular(col.astype(float), start, end))
    return country_shifts(wide, cfg)
