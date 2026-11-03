from datetime import datetime, timedelta

from argus.model import Point, Signal

T = datetime(2026, 9, 2, 11, 40)


def at(i: int) -> datetime:
    return T + timedelta(minutes=10 * i)


def test_truncate_matches_live_segmentation():
    points = [Point(at(0), 100, 5, 9, True), Point(at(1), 80, 5, 9, True), Point(at(2), 6, 5, 0.1, False),
              Point(at(3), 90, 5, 9, True)]
    s = Signal("log_burst", "k", "x", at(0), at(3), at(0), at(0), 100, 5, 9, 276, {}, points)
    t = s.truncate(at(2))
    assert t.end == at(1)
    assert t.total == 180  # the unflagged gap bucket after the last flag is not part of the episode yet
    assert s.truncate(at(-1)) is None
