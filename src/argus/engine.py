"""One tick = reveal signals at `now` → incident book → act: task, Slack, post-mortem, predictions.

`replay` drives ticks over history with a moving `now` (the same loop serves `run` for cron and
`watch` for a resident process). Progress is a cursor in <out>/.argus/state.pkl, so a rerun never repeats a
task or a Slack post.
"""

from __future__ import annotations

import json
import os
import pickle
import shutil
import time
from dataclasses import MISSING, dataclass, field, fields
from datetime import datetime, timedelta
from typing import Protocol

from .config import Config
from .correlate import (
    SEVERITY_ORDER,
    Event,
    Fingerprint,
    Incident,
    IncidentBook,
    IncidentCfg,
    backed_by_new_signature,
)
from .detect import DetectCfg, detect_all
from .detect.security import BotCfg
from .llm.vote import vote
from .model import Signal
from .probe import StoreProbe
from .render.fmt import human, pct
from .render.slack import SlackLog, alert_payload, note_payload
from .render.task import stem
from .routing import Router
from .store import Store
from .timeutil import BUCKET
from .tracker import Tracker
from .triage import Triage, fallback_triage

LOOKBACK = timedelta(hours=2)


class Analyst(Protocol):
    name: str

    def triage(self, incident: Incident, store: Store, now: datetime) -> Triage: ...


class RulesAnalyst:
    name = "rules"

    def __init__(self, router: Router):
        self.router = router

    def triage(self, incident: Incident, store: Store, now: datetime) -> Triage:
        return fallback_triage(incident, self.router)


@dataclass
class TaskRecord:
    task_id: str
    incident_uid: str
    triage: Triage
    fingerprint: Fingerprint
    opened_at: datetime
    opened_lines: int
    opened_clients: int
    slack_ts: str | None = None
    history: list[tuple[datetime, str]] = field(default_factory=list)
    repeats: list[dict] = field(default_factory=list)
    related: list[str] = field(default_factory=list)
    prediction: str | None = None
    last_active: datetime | None = None
    severity: str = "SEV-3"            # worst over the task's incidents


@dataclass
class Memory:
    cursor: datetime | None = None
    incidents: list[Incident] = field(default_factory=list)
    owner: dict[str, str] = field(default_factory=dict)          # signal key → incident uid
    tasks: dict[str, TaskRecord] = field(default_factory=dict)   # task id → record
    by_incident: dict[str, str] = field(default_factory=dict)    # incident uid → task id
    stats: dict[str, int] = field(default_factory=dict)
    predictions: list = field(default_factory=list)


@dataclass
class RunStats:
    ticks: int = 0
    opened: int = 0
    repeats: int = 0
    resolved: int = 0
    blips: int = 0
    predictions: int = 0
    seconds: float = 0.0


class Engine:
    def __init__(self, cfg: Config, store: Store, router: Router, analyst: Analyst, arbiter=None, dedup=None,
                 predictor=None):
        self.cfg, self.store, self.router = cfg, store, router
        self.analyst, self.arbiter, self.dedup, self.predictor = analyst, arbiter, dedup, predictor
        self.detect_cfg = DetectCfg.from_dict(cfg.detect)
        slack = cfg.slack or {}
        self.channel = slack.get("channel", "#app-alerts")
        self.prediction_channel = slack.get("prediction_channel", "#app-alert-predictions")
        self.mentions: dict[str, str] = slack.get("mentions", {})
        self.tracker = Tracker(cfg.paths.out_dir, slack.get("tracker_url", "https://tracker.example.com/browse/{id}"))
        self.slack = SlackLog(cfg.paths.out_dir / "slack-log.json")
        self.state_path = cfg.paths.out_dir / ".argus" / "state.pkl"  # state belongs to these outputs
        self.memory: Memory = _load_memory(self.state_path)
        known = {k: v for k, v in (cfg.incidents or {}).items() if k in IncidentCfg.__dataclass_fields__}
        self.book = IncidentBook(router, StoreProbe(store), IncidentCfg(**known), self.detect_cfg.bots or BotCfg())
        self.book.incidents = self.memory.incidents
        uid_map = {i.uid: i for i in self.book.incidents}
        self.book.owner = {k: uid_map[u] for k, u in self.memory.owner.items() if u in uid_map}

    # --- tick ---------------------------------------------------------------------------------

    def tick(self, now: datetime, signals: list[Signal]) -> list[Event]:
        self.store.set_now(now)
        events = self.book.step(signals, now)
        for event in events:
            self._handle(event, now)
        if self.predictor:
            for prediction in self.predictor.tick(now, signals, self.book):
                self._predict(prediction, now)
        self.memory.cursor = now
        return events

    def incident(self, uid: str) -> Incident:
        return next(i for i in self.book.incidents if i.uid == uid)

    def _handle(self, event: Event, now: datetime) -> None:
        inc = event.incident
        self.memory.stats[event.kind] = self.memory.stats.get(event.kind, 0) + 1
        if event.kind == "blip":
            return
        if event.kind == "opened":
            self._opened(inc, now)
            return
        task_id = self.memory.by_incident.get(inc.uid)
        if task_id is None:
            return
        record = self.memory.tasks[task_id]
        repeat = record.incident_uid != inc.uid
        prefix = f"Повтор {inc.start:%d.%m %H:%M}: " if repeat else ""
        if event.kind == "updated":
            text = f"{prefix}{event.detail}"
            if "переназначено" in event.detail and not repeat:
                record.triage = self._analyse(inc, now)
            if SEVERITY_ORDER[inc.severity] > SEVERITY_ORDER[record.severity]:
                self._escalate(record, inc, now, repeat)
        elif event.kind == "resolved":
            text = (f"{prefix}закрыт: ≈{human(inc.impact.clients)} клиентов, пик ошибок "
                    f"{pct(inc.impact.peak_error_rate)}, {inc.severity}")
            for r in record.repeats:
                if r["uid"] == inc.uid:
                    r["text"] += f" Закрыт {now:%d.%m %H:%M}, итог ≈{human(inc.impact.clients)} клиентов."
        elif event.kind == "reopened":
            text = f"{prefix}возобновился: уровень причины снова выше обычного"
        else:
            return
        record.history.append((now, text))
        record.last_active = now
        emoji = {"resolved": "✅", "reopened": "🔁", "updated": "ℹ️"}[event.kind]
        if record.slack_ts:
            self.slack.reply(record.slack_ts, note_payload(self.channel, f"{emoji} {text}"), now,
                             {"incident": task_id, "event": event.kind})
            if event.kind in ("resolved", "reopened", "updated") and not repeat:
                payload = alert_payload(inc, record.triage, self.channel, self.tracker.url(task_id),
                                        mention=self.mentions.get(record.triage.assignee),
                                        resolved=inc.status == "resolved")
                self.slack.update(record.slack_ts, payload, now, {"incident": task_id, "event": f"{event.kind}-root"})
        self._write(record)

    def _related(self, now: datetime, exclude: str | None = None) -> list[dict]:
        recent = [r for r in self.memory.tasks.values() if r.last_active and now - r.last_active <= timedelta(hours=72)
                  and r.task_id != exclude]
        return [{"task": r.task_id, "title": r.triage.title, "assignee": r.triage.assignee,
                 "opened": f"{r.opened_at:%d.%m %H:%M}", "repeats": len(r.repeats)} for r in recent[-5:]]

    def _analyse(self, inc: Incident, now: datetime) -> Triage:
        if isinstance(self.analyst, RulesAnalyst):
            triage = self.analyst.triage(inc, self.store, now)
        else:
            triage = self.analyst.triage(inc, self.store, now, related=self._related(now, exclude=inc.task_id))
        if self.arbiter:
            self.arbiter.review(inc, triage, self.store, now, self.router)
        elif triage.source != "rules":  # analyst alone: still may not overrule a new-signature routing
            role, needs_human, note = vote(inc.role, triage.assignee, None, backed_by_new_signature(inc, self.router))
            triage.assignee, triage.needs_human = role, needs_human
            triage.arbiter_note = note or triage.arbiter_note
            inc.role = role
        return triage

    def _escalate(self, record: TaskRecord, inc: Incident, now: datetime, repeat: bool) -> None:
        """A task's incident got worse than the task ever was: re-analyse it and tell the channel."""
        before, record.severity = record.severity, inc.severity
        if repeat:  # the task text describes the first, milder occurrence: analyse the escalated one
            record.triage = self._analyse(inc, now)
        record.history.append((now, f"эскалация {before} → {inc.severity}"))
        if record.slack_ts:
            self.slack.reply(record.slack_ts, note_payload(
                self.channel, f"⬆️ *Эскалация {record.task_id}: {before} → {inc.severity}.* {record.triage.title}"),
                now, {"incident": record.task_id, "event": "escalated"}, broadcast=True)

    def _opened(self, inc: Incident, now: datetime) -> None:
        summary = (f"открыт ({inc.reason}): ≈{human(inc.impact.clients)} клиентов, "
                   f"{human(inc.impact.lines)} строк ошибок, пик {pct(inc.impact.peak_error_rate)}, {inc.severity}")
        rules = fallback_triage(inc, self.router)
        parent = self.dedup.match(inc, rules, self.memory, now) if self.dedup else None
        if parent is not None:  # checked before the LLM: a repeat costs no model call
            self._repeat(parent, inc, rules, now, f"{summary}; {self.dedup.last_reason}")
            return
        triage = rules if isinstance(self.analyst, RulesAnalyst) and not self.arbiter else self._analyse(inc, now)
        ref = self.tracker.create(inc, triage, history=[(now, summary)])
        record = TaskRecord(ref.id, inc.uid, triage, inc.fingerprint(), now, inc.impact.lines, inc.impact.clients,
                            history=[(now, summary)], last_active=now, severity=inc.severity)
        self.memory.tasks[ref.id] = record
        self.memory.by_incident[inc.uid] = ref.id
        record.slack_ts = self.slack.post(
            alert_payload(inc, triage, self.channel, self.tracker.url(ref.id),
                          mention=self.mentions.get(triage.assignee)),
            now, {"incident": ref.id, "event": "opened", "severity": inc.severity, "assignee": triage.assignee})
        self._write(record)

    def _repeat(self, record: TaskRecord, inc: Incident, triage: Triage, now: datetime, summary: str) -> None:
        inc.task_id = record.task_id
        self.memory.by_incident[inc.uid] = record.task_id
        text = f"{triage.summary} Обнаружен {now:%d.%m %H:%M}, {summary}."
        record.repeats.append({"uid": inc.uid, "start": f"{inc.start:%d.%m %H:%M}", "text": text})
        if SEVERITY_ORDER[inc.severity] > SEVERITY_ORDER[record.severity]:
            self._escalate(record, inc, now, repeat=True)
        record.history.append((now, f"повтор: {summary}"))
        record.last_active = now
        major = inc.severity in ("SEV-1", "SEV-2")
        if record.slack_ts:
            self.slack.reply(record.slack_ts, note_payload(
                self.channel, f"🔁 *Повтор {record.task_id}* ({inc.severity}): {triage.title}. {summary}."),
                now, {"incident": record.task_id, "event": "repeat"}, broadcast=major)
        self._write(record)

    def _predict(self, prediction, now: datetime) -> None:
        self.memory.stats["predicted"] = self.memory.stats.get("predicted", 0) + 1
        self.memory.predictions.append(prediction)
        self.slack.post(prediction.payload(self.prediction_channel), now,
                        {"event": "prediction", "kind": prediction.kind, "target": prediction.target,
                         "window": [f"{prediction.window_start:%Y-%m-%dT%H:%M}Z",
                                    f"{prediction.window_end:%Y-%m-%dT%H:%M}Z"]})
        record = self.memory.tasks.get(prediction.target)
        if record:
            record.prediction = (f"{now:%d.%m %H:%M} — риск повтора в окне {prediction.window_start:%d.%m %H:%M}–"
                                 f"{prediction.window_end:%H:%M} UTC")
            record.history.append((now, f"прогноз в #app-alert-predictions: {record.prediction}"))
            self._write(record)

    def _write(self, record: TaskRecord) -> None:
        inc = self.incident(record.incident_uid)
        self.tracker.write(inc, record.triage, record.history, record.repeats, record.related, record.prediction,
                           record.severity)

    # --- persistence --------------------------------------------------------------------------

    def rerender(self) -> None:
        """Rewrite every task and post-mortem from saved state (after a template change), no model calls."""
        keep = set()
        for record in self.memory.tasks.values():
            inc = self.incident(record.incident_uid)
            inc.slug = None
            inc.slug = stem(inc)
            keep.add(inc.slug + ".md")
            self._write(record)
        for folder in (self.tracker.tasks_dir, self.tracker.pm_dir):
            for path in folder.glob("ARG-*.md"):
                if path.name not in keep:
                    path.unlink()
        self.save()

    def save(self) -> None:
        self.memory.incidents = self.book.incidents
        self.memory.owner = {k: i.uid for k, i in self.book.owner.items()}
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_bytes(pickle.dumps(self.memory))
        os.replace(tmp, self.state_path)  # a kill mid-write leaves the previous state intact
        summary = {"cursor": self.memory.cursor.isoformat() if self.memory.cursor else None,
                   "stats": self.memory.stats,
                   "tasks": [{"id": r.task_id, "title": r.triage.title, "assignee": r.triage.assignee,
                              "severity": r.severity,
                              "status": self.incident(r.incident_uid).status,
                              "file": f"tasks/{stem(self.incident(r.incident_uid))}.md",
                              "repeats": len(r.repeats)} for r in self.memory.tasks.values()]}
        (self.state_path.parent / "state.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))


def replay(engine: Engine, since: datetime | None = None, until: datetime | None = None,
           max_seconds: float | None = None) -> RunStats:
    """Process ticks after the saved cursor up to `until` (default: end of data).

    State is saved after every tick that produced output, so a killed pass resumes without repeating a task
    or a post; `max_seconds` stops cleanly before a scheduler's deadline (the next pass continues).
    """
    started = time.monotonic()
    t0, t1 = engine.store.time_range()
    start = since or t0
    if engine.memory.cursor is not None:
        start = max(start, engine.memory.cursor + BUCKET)
    end = min(until or t1, t1)
    stats = RunStats()
    if start > end:
        return stats
    engine.store.set_now(end + BUCKET)
    signals = detect_all(engine.store, engine.detect_cfg)
    now = start
    last_post = engine.slack.entries[-1]["ts"] if engine.slack.entries else None
    while now <= end:
        visible = [v for v in (s.truncate(now) for s in signals if s.detected_at <= now)
                   if v and v.end >= now - LOOKBACK]
        events = engine.tick(now, visible)
        if events or engine.slack.entries and engine.slack.entries[-1]["ts"] != last_post:
            engine.save()
            last_post = engine.slack.entries[-1]["ts"] if engine.slack.entries else None
        for event in events:
            if event.kind == "opened":
                stats.opened += 1
            elif event.kind == "resolved":
                stats.resolved += 1
            elif event.kind == "blip":
                stats.blips += 1
        stats.ticks += 1
        now += BUCKET
        if max_seconds is not None and time.monotonic() - started > max_seconds:
            break
    stats.repeats = sum(len(r.repeats) for r in engine.memory.tasks.values())
    stats.predictions = engine.memory.stats.get("predicted", 0)
    engine.save()
    stats.seconds = round(time.monotonic() - started, 1)
    return stats


def _load_memory(path) -> Memory:
    if not path.exists():
        return Memory()
    try:
        memory = pickle.loads(path.read_bytes())
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"cannot read run state {path}: {e}. Restore it or start over with --fresh.") from e
    for obj in [memory, *memory.incidents, *memory.tasks.values()]:
        _fill_defaults(obj)  # state written by an older version lacks newer fields
    return memory


def _fill_defaults(obj) -> None:
    for f in fields(obj):
        if f.name not in obj.__dict__:
            if f.default is not MISSING:
                setattr(obj, f.name, f.default)
            elif f.default_factory is not MISSING:
                setattr(obj, f.name, f.default_factory())


def reset_outputs(cfg: Config) -> None:
    """Fresh run: drop state and the generated outputs (only the paths Argus writes)."""
    out = cfg.paths.out_dir
    for d in (out / "tasks", out / "postmortems"):
        if d.exists():
            shutil.rmtree(d)
    if (out / ".argus").exists():
        shutil.rmtree(out / ".argus")
    (out / "slack-log.json").unlink(missing_ok=True)


def build_engine(cfg: Config, llm: str | None = None) -> Engine:
    router = Router.load(cfg.paths.routing)
    store = Store(cfg.paths.db)
    mode = (llm or cfg.llm.get("mode") or "auto").lower()
    analyst, arbiter = RulesAnalyst(router), None
    if mode != "off":
        from .llm import make_analyst_and_arbiter
        analyst, arbiter = make_analyst_and_arbiter(cfg, router, mode)
    dedup = predictor = None
    if cfg.dedup.get("enabled", True):
        from .dedup import Dedup
        dedup = Dedup(cfg.dedup, router)
    if cfg.predict.get("enabled", True):
        from .predict import Predictor
        predictor = Predictor(cfg.predict, router, store)
    return Engine(cfg, store, router, analyst, arbiter, dedup, predictor)
