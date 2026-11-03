"""Core data types shared by detectors, correlation, the engine and renderers."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

ROLES = ("DBA", "PaaS Engineer", "SEO Specialist", "Backend Lead", "Security Lead")


@dataclass(frozen=True)
class Point:
    ts: datetime
    value: float
    baseline: float
    score: float
    flagged: bool


@dataclass
class Signal:
    """One anomalous episode of one series (a log template, a metric, a country)."""

    kind: str            # log_burst | rps_artifact | rps_shift | cpu_high | traffic_shift | country_shift
    key: str             # template id, metric name or country code
    label: str           # human-readable: template text, metric name, country
    start: datetime      # first flagged bucket
    end: datetime        # last flagged bucket
    detected_at: datetime
    peak_at: datetime
    value: float         # observed value at the peak
    baseline: float      # expected value at the peak
    score: float         # robust z (or ratio) at the peak
    total: float = 0.0   # sum of values over [start, end]
    attrs: dict[str, Any] = field(default_factory=dict)
    points: list[Point] = field(default_factory=list, repr=False)

    @property
    def ratio(self) -> float:
        return self.value / self.baseline if self.baseline else float("inf")

    def truncate(self, now: datetime) -> Signal | None:
        """The signal as it looked at `now` (None if not detected yet). Exact: recomputed from points."""
        if self.detected_at > now:
            return None
        if self.end <= now or not self.points:
            return self
        flagged = [p for p in self.points if p.ts <= now and p.flagged]
        end = flagged[-1].ts if flagged else self.start
        pts = [p for p in self.points if p.ts <= end]  # live segmentation ends at the last flagged bucket
        peak = max(flagged, key=lambda p: p.value) if flagged else pts[-1]
        return replace(self, end=end, peak_at=peak.ts, value=peak.value, baseline=peak.baseline,
                       score=peak.score, total=sum(p.value for p in pts), points=pts)
