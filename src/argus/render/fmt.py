"""Russian number and duration formatting for tasks and Slack."""

from __future__ import annotations


def _comma(s: str) -> str:
    return s.replace(".", ",")


def human(n: float | None) -> str:
    if n is None:
        return "—"
    a = abs(n)
    if a >= 1e9:
        return _comma(f"{n / 1e9:.2f}") + " млрд"
    if a >= 1e6:
        return _comma(f"{n / 1e6:.2f}") + " млн"
    if a >= 1e3:
        return _comma(f"{n / 1e3:.1f}") + " тыс."
    return f"{n:.0f}" if float(n).is_integer() else _comma(f"{n:.1f}")


def pct(x: float | None) -> str:
    if x is None:
        return "—"
    v = x * 100
    return _comma(f"{v:.1f}" if abs(v) >= 1 else f"{v:.2f}") + " %"


def dur(minutes: float) -> str:
    minutes = int(round(minutes))
    if minutes < 60:
        return f"{minutes} мин"
    h, m = divmod(minutes, 60)
    if h >= 48:
        return f"{h // 24} д {h % 24} ч"
    return f"{h} ч {m} мин" if m else f"{h} ч"
