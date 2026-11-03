"""Causal building blocks: every value at bucket t is computed from buckets < t only.

Series are expected on a regular 10-minute grid (use `regular`). Seasonality is daily: the
baseline is the median of the same time of day over previous days, which shrugs off one bad day.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from datetime import datetime

import numpy as np
import pandas as pd

from ..timeutil import BUCKETS_PER_DAY

MAD_TO_SIGMA = 1.4826


def regular(s: pd.Series, start: datetime, end: datetime, fill: float | None = None) -> pd.Series:
    """Reindex onto the 10-minute grid [start, end]; gaps become `fill` (NaN by default)."""
    idx = pd.date_range(start, end, freq="10min")
    out = s.reindex(idx)
    return out.fillna(fill) if fill is not None else out


def seasonal_baseline(s: pd.Series, days: int = 7, min_days: int = 2, fallback: int = 12) -> pd.Series:
    """Median of the same time of day over the previous `days` days.

    With fewer than `min_days` days of history, the median of the previous `fallback` buckets
    (`fallback=0`: NaN, i.e. "no opinion yet").
    """
    lagged = np.column_stack([s.shift(d * BUCKETS_PER_DAY).to_numpy() for d in range(1, days + 1)])
    available = np.sum(~np.isnan(lagged), axis=1)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # rows with no history → NaN, replaced below
        seasonal = np.nanmedian(lagged, axis=1)
    if fallback <= 0:
        return pd.Series(np.where(available >= min_days, seasonal, np.nan), index=s.index)
    trailing = s.shift(1).rolling(fallback, min_periods=3).median().to_numpy()
    return pd.Series(np.where(available >= min_days, seasonal, trailing), index=s.index)


def robust_scale(resid: pd.Series, window: int = 432, min_periods: int = 24) -> pd.Series:
    """1.4826 × median |residual| over the previous `window` buckets (3 days by default)."""
    return MAD_TO_SIGMA * resid.abs().shift(1).rolling(window, min_periods=min_periods).median()


@dataclass(frozen=True)
class Episode:
    start: datetime        # first flagged bucket
    end: datetime          # last flagged bucket
    detected_at: datetime  # bucket where the episode reached min_len flags
    n_flagged: int


def segment(flags: pd.Series, min_len: int = 1, max_gap: int = 2) -> list[Episode]:
    """Group flagged buckets into episodes.

    Runs separated by at most `max_gap` unflagged buckets merge; episodes with fewer than
    `min_len` flagged buckets are dropped.
    """
    episodes: list[Episode] = []
    idx = flags.index
    pos = np.flatnonzero(flags.to_numpy(dtype=bool))
    if len(pos) == 0:
        return episodes
    groups: list[list[int]] = [[pos[0]]]
    for p in pos[1:]:
        if p - groups[-1][-1] - 1 <= max_gap:
            groups[-1].append(p)
        else:
            groups.append([p])
    for g in groups:
        if len(g) >= min_len:
            episodes.append(Episode(idx[g[0]].to_pydatetime(), idx[g[-1]].to_pydatetime(),
                                    idx[g[min_len - 1]].to_pydatetime(), len(g)))
    return episodes
