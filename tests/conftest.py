"""Test helpers: write tiny datasets in exactly the format of the real export."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

T0 = datetime(2026, 8, 24, 11, 10)  # first metric point of the real data


def epoch_ms(ts: datetime) -> int:
    return int((ts - datetime(1970, 1, 1)).total_seconds() * 1000)


def log_line(ts: datetime, message: str, *, status: str | None = "503 Service Unavailable",
             user_id: str | None = None, ip: str = "10.0.0.1", country: str = "US",
             isp: str = "Comcast", host: str = "kube0001.infra.internal", cls: str = "app") -> str:
    client = json.dumps({"country_code": country, "country_name": country, "region_code": f"{country}-X",
                         "region_name": "X", "city_name": "City", "isp_name": isp}, indent=4)
    row = {"request_ip": ip, "application_client": client, "source": host, "message": message,
           "class": cls, "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}
    if status is not None:
        row["response_code"] = status
    if user_id is not None:
        row["user_id"] = user_id
    return json.dumps(row)


def write_dataset(root: Path, *, logs: list[str] | None = None, points: int = 6,
                  rps: list[float] | None = None, cpu: list[float] | None = None,
                  countries: dict[str, list[float | None]] | None = None,
                  endpoints: dict[str, list[float | None]] | None = None) -> Path:
    """Write the five input files. Metric lists have `points` values starting at T0, 10-min step."""
    root.mkdir(parents=True, exist_ok=True)
    times = [T0 + timedelta(minutes=10 * i) for i in range(points)]
    rps = rps or [1000.0] * points
    cpu = cpu or [0.2] * points
    countries = countries or {"US": [500.0] * points, "BR": [100.0] * points}
    endpoints = endpoints or {"front:video:view": [120.0] * points}

    def fmt(v: float | None) -> str:
        return "undefined" if v is None else repr(float(v))

    (root / "logs.json").write_text("\n".join(logs or []) + "\n")
    (root / "rps.csv").write_text('"Time","Current"\n' + "\n".join(
        f"{epoch_ms(t)},{fmt(v)}" for t, v in zip(times, rps)))
    (root / "cpu-usage.csv").write_text('"Time","AVG Current"\n' + "\n".join(
        f"{epoch_ms(t)},{fmt(v)}" for t, v in zip(times, cpu)))
    for name, table in (("rps-by-country.csv", countries), ("endpoint-timings-ms.csv", endpoints)):
        cols = list(table)
        lines = ['"Time",' + ",".join(f'"{c}"' for c in cols)]
        lines += [f"{epoch_ms(t)}," + ",".join(fmt(table[c][i]) for c in cols) for i, t in enumerate(times)]
        (root / name).write_text("\n".join(lines))
    return root


@pytest.fixture
def dataset(tmp_path: Path):
    """Factory: dataset(**kwargs) -> data dir."""
    def make(**kwargs) -> Path:
        return write_dataset(tmp_path / "data", **kwargs)
    return make
