import math
from datetime import datetime

from conftest import log_line

from argus.ingest import ingest, load_wide_csv
from argus.store import Store
from argus.timeutil import bucket_end


def test_bucket_end_alignment():
    assert bucket_end(datetime(2026, 8, 24, 11, 10, 1)) == datetime(2026, 8, 24, 11, 20)
    assert bucket_end(datetime(2026, 8, 24, 11, 20, 0)) == datetime(2026, 8, 24, 11, 30)


def test_csv_undefined_is_nan(dataset):
    data = dataset(points=3, countries={"US": [5.0, 6.0, 7.0], "BR": [1.0, None, 3.0]})
    long = load_wide_csv(data / "rps-by-country.csv", "country")
    br = long[long.country == "BR"]
    assert len(br) == 2  # the 'undefined' point is absent, not zero
    assert not any(math.isclose(v, 0.0) for v in br.value)


def test_status_code_parsed(dataset, tmp_path):
    logs = [log_line(datetime(2026, 8, 24, 11, 10, 1), "boom 1", status="503 Service Unavailable"),
            log_line(datetime(2026, 8, 24, 11, 10, 2), "boom 2", status=None)]
    ingest(dataset(logs=logs), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb")
    assert store.df("SELECT status FROM logs ORDER BY ts").status.tolist()[0] == 503
    assert store.df("SELECT count(*) n FROM logs WHERE status IS NULL").n[0] == 1


def test_ingest_aggregates_by_bucket_end(dataset, tmp_path):
    logs = [log_line(datetime(2026, 8, 24, 11, 10, 1), "Timeout 0 wait exceeded", user_id="7"),
            log_line(datetime(2026, 8, 24, 11, 19, 59), "Timeout 0 wait exceeded", ip="10.0.0.2"),
            log_line(datetime(2026, 8, 24, 11, 20, 0), "Timeout 0 wait exceeded")]
    stats = ingest(dataset(logs=logs), tmp_path / "var")
    assert stats.log_rows == 3 and stats.templates == 1
    agg = Store(tmp_path / "var" / "argus.duckdb").df("SELECT bucket, n, clients FROM agg_tpl_10m ORDER BY bucket")
    assert agg.bucket.tolist() == [datetime(2026, 8, 24, 11, 20), datetime(2026, 8, 24, 11, 30)]
    assert agg.n.tolist() == [2, 1]
    assert agg.clients.tolist()[0] == 2  # user 7 + anonymous ip 10.0.0.2


def test_store_now_guard(dataset, tmp_path):
    logs = [log_line(datetime(2026, 8, 24, 11, 15), "a"), log_line(datetime(2026, 8, 24, 11, 30), "b")]
    ingest(dataset(logs=logs), tmp_path / "var")
    store = Store(tmp_path / "var" / "argus.duckdb", now=datetime(2026, 8, 24, 11, 30))
    assert store.df("SELECT count(*) n FROM logs").n[0] == 1  # the row at `now` is not visible yet
    assert store.df("SELECT max(ts) t FROM metric_rps").t[0] == datetime(2026, 8, 24, 11, 30)
    store.set_now(datetime(2026, 8, 24, 11, 40))
    assert store.df("SELECT count(*) n FROM logs").n[0] == 2
