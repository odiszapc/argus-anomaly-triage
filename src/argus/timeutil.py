"""Time conventions.

All timestamps are naive UTC. A bucket is labelled by its END: label T covers [T-10m, T),
the same convention the metric exports use. At tick `now`, buckets with label <= now are complete.
"""

from __future__ import annotations

from datetime import datetime, timedelta

BUCKET = timedelta(minutes=10)
BUCKET_S = 600
BUCKETS_PER_DAY = 144


def bucket_end(ts: datetime) -> datetime:
    floor = ts.replace(second=0, microsecond=0, minute=ts.minute - ts.minute % 10)
    return floor + BUCKET


def floor_bucket(ts: datetime) -> datetime:
    """Latest bucket label that is complete at `ts`."""
    return ts.replace(second=0, microsecond=0, minute=ts.minute - ts.minute % 10)


def fmt(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "—"


def fmt_short(ts: datetime | None) -> str:
    return ts.strftime("%d.%m %H:%M") if ts else "—"


def sql_ts(ts: datetime) -> str:
    """Timestamp literal for DuckDB (values come from our own datetimes, never from users)."""
    return f"TIMESTAMP '{ts.strftime('%Y-%m-%d %H:%M:%S.%f')}'"


def parse_ts(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    return datetime.fromisoformat(value.replace("Z", "")).replace(tzinfo=None)
