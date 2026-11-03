"""Task and post-mortem markdown (Jinja templates in ./templates)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ..correlate import Incident
from ..triage import Triage
from .fmt import dur, human, pct

VOTERS = {"rules": "правила", "analyst": "аналитик", "arbiter": "арбитр"}

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), trim_blocks=True, lstrip_blocks=True,
                   keep_trailing_newline=True, undefined=StrictUndefined)
_env.filters.update(
    ts=lambda t: t.strftime("%Y-%m-%d %H:%M") if t else "—",
    short=lambda t: t.strftime("%d.%m %H:%M") if t else "—",
    j=lambda v: json.dumps(v, ensure_ascii=False), human=human, pct=pct)


def ttd_minutes(incident: Incident) -> int:
    """From the start of the first anomalous bucket (label - 10 min) to the alert."""
    return int((incident.detected_at - incident.start).total_seconds() // 60) + 10


def stem(incident: Incident) -> str:
    return incident.slug or f"{incident.task_id}-{incident.component}-{incident.start:%Y%m%d-%H%M}"


def _fingerprint(incident: Incident) -> str:
    fp = incident.fingerprint()
    return f"{fp.component}|{','.join(fp.templates)}|{fp.country or ''}"


def _countries(incident: Incident) -> str:
    return ", ".join(f"{c} {human(n)}" for c, n in incident.impact.top_countries)


def _votes(triage: Triage) -> str:
    return " · ".join(f"{VOTERS.get(k, k)} — {v}" for k, v in triage.votes.items())


def _signals(incident: Incident, limit: int = 12):
    ranked = sorted(incident.signals.values(), key=lambda s: -s.total)[:limit]
    return sorted(ranked, key=lambda s: s.start)


def render_task(incident: Incident, triage: Triage, history: list[tuple[datetime, str]],
                repeats: list[dict] | None = None, related: list[str] | None = None,
                severity: str | None = None) -> str:
    return _env.get_template("task.md.j2").render(severity=severity or incident.severity, 
        id=incident.task_id, title=triage.title.replace("\n", " "), incident=incident, triage=triage,
        status="resolved" if incident.resolved_at else "open", ttd=ttd_minutes(incident),
        fingerprint=_fingerprint(incident), postmortem_path=f"postmortems/{stem(incident)}.md",
        signals=_signals(incident), history=history, repeats=repeats or [], related=related or [],
        countries=_countries(incident), votes=_votes(triage))


def render_postmortem(incident: Incident, triage: Triage, history: list[tuple[datetime, str]],
                      prediction: str | None = None, severity: str | None = None) -> str:
    key_signals = [(s.start, f"начало сигнала «{s.label[:70]}»") for s in _signals(incident, 8)]
    timeline = sorted(key_signals + list(history), key=lambda x: x[0])
    end = incident.resolved_at or incident.end
    minutes = (end - incident.start).total_seconds() / 60 + 10
    return _env.get_template("postmortem.md.j2").render(
        severity=severity or incident.severity, id=incident.task_id, title=triage.title.replace("\n", " "),
        incident=incident, triage=triage, ttd=ttd_minutes(incident), duration=dur(minutes), timeline=timeline,
        prediction=prediction, task_link=f"../tasks/{stem(incident)}.md", signals=list(incident.signals.values()),
        countries=_countries(incident))
