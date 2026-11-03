from datetime import datetime

import numpy as np
import pandas as pd

from argus.detect.countries import CountryCfg, country_shifts
from argus.detect.logs import LogCfg, log_bursts
from argus.detect.metrics import MetricCfg, rps_signals
from argus.detect.security import BotFeatures, is_bot_like

T0 = datetime(2026, 8, 24, 0, 10)
DAY = 144


def idx(n: int) -> pd.DatetimeIndex:
    return pd.date_range(T0, periods=n, freq="10min")


def daily(n: int, level: float, swing: float = 0.3) -> pd.Series:
    """A smooth daily cycle, identical every day."""
    t = np.arange(n) % DAY
    return pd.Series(level * (1 + swing * np.sin(2 * np.pi * t / DAY)), index=idx(n))


# --- log templates -------------------------------------------------------------------------------

def test_burst_detected():
    rng = np.random.default_rng(0)
    counts = pd.DataFrame({"a": rng.poisson(5, 3 * DAY).astype(float)}, index=idx(3 * DAY))
    counts.iloc[400:403, 0] = 500
    signals = log_bursts(counts, {"a": "Redis failure"}, LogCfg())
    assert len(signals) == 1
    s = signals[0]
    assert (s.kind, s.key, s.label) == ("log_burst", "a", "Redis failure")
    assert (s.start, s.end) == (idx(3 * DAY)[400], idx(3 * DAY)[402])
    assert s.total == 1500 and s.value == 500


def test_no_burst_during_warmup():
    counts = pd.DataFrame({"a": np.full(3 * DAY, 5.0)}, index=idx(3 * DAY))
    counts.iloc[10, 0] = 900  # inside the first 6 hours: no baseline to trust yet
    assert log_bursts(counts, {"a": "x"}, LogCfg()) == []


def test_new_template_is_marked():
    counts = pd.DataFrame({"b": np.zeros(3 * DAY)}, index=idx(3 * DAY))
    counts.iloc[300:302, 0] = 200
    [s] = log_bursts(counts, {"b": "Topology is closed"}, LogCfg())
    assert s.attrs["new_template"] is True


# --- rps / cpu -----------------------------------------------------------------------------------

def test_rps_spike_without_corroboration_is_artifact():
    n = 3 * DAY
    rps, cpu, countries = daily(n, 80_000), daily(n, 30), daily(n, 20_000)
    rps.iloc[350] *= 2
    signals = rps_signals(rps, cpu, countries, MetricCfg())
    assert [s.kind for s in signals] == ["rps_artifact"]
    assert signals[0].start == idx(n)[350]


def test_rps_spike_with_cpu_is_real():
    n = 3 * DAY
    rps, cpu, countries = daily(n, 80_000), daily(n, 30), daily(n, 20_000)
    rps.iloc[350:353] *= 2
    cpu.iloc[350:353] *= 2.5
    kinds = {s.kind for s in rps_signals(rps, cpu, countries, MetricCfg())}
    assert "rps_shift" in kinds and "rps_artifact" not in kinds


def test_artifact_does_not_poison_baseline():
    n = 4 * DAY
    rps, cpu, countries = daily(n, 80_000), daily(n, 30), daily(n, 20_000)
    for day in (0, 1, 2):  # the same slot doubles three days in a row (a scheduled artifact)
        rps.iloc[day * DAY + 50] *= 2
    signals = rps_signals(rps, cpu, countries, MetricCfg())
    assert all(s.kind == "rps_artifact" for s in signals)
    assert idx(n)[3 * DAY + 50] not in {s.start for s in signals}  # the normal value on day 4 is not a "drop"


# --- countries -----------------------------------------------------------------------------------

def test_country_missing_is_not_zero():
    n = 3 * DAY
    wide = pd.DataFrame({"US": daily(n, 10_000), "BR": daily(n, 1_000)})
    wide.loc[wide.index[2 * DAY::2], "BR"] = np.nan  # topk dropped BR every other point on day 3
    assert country_shifts(wide, CountryCfg()) == []


def test_country_shift_vs_global():
    n = 3 * DAY
    wide = pd.DataFrame({"US": daily(n, 10_000), "BR": daily(n, 1_000)})
    wide.iloc[2 * DAY + 60:2 * DAY + 72, 1] *= 2  # BR doubles for 2 hours
    [s] = country_shifts(wide, CountryCfg())
    assert (s.kind, s.key, s.attrs["direction"]) == ("country_shift", "BR", "up")

    everyone = pd.DataFrame({"US": daily(n, 10_000), "BR": daily(n, 1_000)})
    everyone.iloc[2 * DAY + 60:2 * DAY + 72, :] *= 2  # global growth is not an SEO signal
    assert country_shifts(everyone, CountryCfg()) == []


# --- security ------------------------------------------------------------------------------------

def test_bot_like_features():
    seedbox = BotFeatures(top_isp="RapidSeedbox Ltd", top_share=0.52, top_rotation=1.0, prior_share=0.0,
                          anon_share=0.98, requests=17764)
    mobile = BotFeatures(top_isp="Reliance Jio Infocomm Limited", top_share=0.11, top_rotation=0.99,
                         prior_share=0.10, anon_share=0.92, requests=16247)
    assert is_bot_like(seedbox)[0] is True
    assert is_bot_like(mobile)[0] is False


# --- adapters over the store ---------------------------------------------------------------------

def test_bot_features_from_logs(dataset, tmp_path):
    from datetime import timedelta

    from conftest import T0 as DATA_T0
    from conftest import log_line

    from argus.detect.security import bot_features
    from argus.ingest import ingest
    from argus.store import Store

    window = DATA_T0 + timedelta(hours=30)
    prior = [log_line(DATA_T0 + timedelta(hours=10, seconds=i), "Adapter failure", ip=f"10.1.0.{i % 50}",
                      isp="Comcast") for i in range(200)]
    attack = [log_line(window + timedelta(seconds=i / 10), "Adapter failure", ip=f"172.16.{i // 250}.{i % 250}",
                       isp="SeedBox Ltd") for i in range(1200)]
    normal = [log_line(window + timedelta(seconds=i), "Adapter failure", ip=f"10.2.0.{i % 40}", isp="Comcast")
              for i in range(800)]
    ingest(dataset(logs=prior + attack + normal, points=6 * 33), tmp_path / "var")
    f = bot_features(Store(tmp_path / "var" / "argus.duckdb"), window, window + timedelta(minutes=20))
    assert f.top_isp == "SeedBox Ltd"
    assert round(f.top_share, 2) == 0.6 and f.top_rotation == 1.0 and f.prior_share == 0.0
    assert is_bot_like(f)[0] is True


def test_detect_all_finds_burst_through_store(dataset, tmp_path):
    from datetime import timedelta

    from conftest import T0 as DATA_T0
    from conftest import log_line

    from argus.detect import detect_all
    from argus.ingest import ingest
    from argus.store import Store

    quiet = [log_line(DATA_T0 + timedelta(minutes=10 * i, seconds=5), "Redis failure") for i in range(3 * DAY)]
    burst_at = DATA_T0 + timedelta(days=2, hours=3)
    burst = [log_line(burst_at + timedelta(seconds=i), "Redis failure") for i in range(400)]
    ingest(dataset(logs=quiet + burst, points=3 * DAY), tmp_path / "var")
    signals = detect_all(Store(tmp_path / "var" / "argus.duckdb"))
    bursts = [s for s in signals if s.kind == "log_burst"]
    assert len(bursts) == 1 and bursts[0].label == "Redis failure"
    assert bursts[0].start == datetime(2026, 8, 26, 14, 20)


def test_hourly_cron_bursts_on_first_day_are_not_anomalies():
    values = np.full(DAY, 20.0)
    values[3::6] = 2500  # an hourly job, before any daily history exists
    counts = pd.DataFrame({"a": values}, index=idx(DAY))
    late = [s for s in log_bursts(counts, {"a": "Timeout <N> wait exceeded"}, LogCfg()) if s.start >= idx(DAY)[72]]
    assert late == []
