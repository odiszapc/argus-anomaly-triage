from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from argus.detect.baseline import robust_scale, seasonal_baseline, segment

T0 = datetime(2026, 8, 24, 0, 10)


def grid(values) -> pd.Series:
    idx = pd.date_range(T0, periods=len(values), freq="10min")
    return pd.Series(np.asarray(values, dtype=float), index=idx)


def test_baseline_is_causal():
    rng = np.random.default_rng(1)
    s = grid(rng.poisson(100, 144 * 6))
    cut = 144 * 4 + 17
    spoiled = s.copy()
    spoiled.iloc[cut + 1:] = 1e9
    pd.testing.assert_series_equal(seasonal_baseline(s).iloc[:cut + 1], seasonal_baseline(spoiled).iloc[:cut + 1])
    pd.testing.assert_series_equal(robust_scale(s - seasonal_baseline(s)).iloc[:cut + 1],
                                   robust_scale(spoiled - seasonal_baseline(spoiled)).iloc[:cut + 1])


def test_seasonal_uses_same_time_of_day():
    days = [np.arange(144, dtype=float) for _ in range(5)]
    days[3][50] = 10_000  # one odd day must not move the median
    s = grid(np.concatenate(days))
    assert seasonal_baseline(s).iloc[144 * 4 + 50] == 50


def test_fallback_on_short_history():
    s = grid([10.0] * 20 + [100.0])
    assert seasonal_baseline(s, fallback=12).iloc[20] == 10.0


def test_no_fallback_gives_nan_on_short_history():
    s = grid([10.0] * 20 + [100.0])
    assert np.isnan(seasonal_baseline(s, fallback=0).iloc[20])


def test_segment_merges_small_gaps():
    flags = grid([0, 1, 1, 0, 0, 1, 0, 0, 0, 1]).astype(bool)
    episodes = segment(flags, max_gap=2)
    assert [(e.start, e.end) for e in episodes] == [
        (T0 + timedelta(minutes=10), T0 + timedelta(minutes=50)),
        (T0 + timedelta(minutes=90), T0 + timedelta(minutes=90)),
    ]


def test_segment_min_len_sets_detection_time():
    flags = grid([0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0]).astype(bool)
    episodes = segment(flags, min_len=2, max_gap=0)
    assert len(episodes) == 1  # the lone flag at position 7 is too short
    assert episodes[0].start == T0 + timedelta(minutes=10)
    assert episodes[0].detected_at == T0 + timedelta(minutes=20)
    assert episodes[0].end == T0 + timedelta(minutes=30)
