"""Signals → incidents, with a lifecycle: pending → open → resolved (or a pending spike → blip).

Attach rules (ops partition):
- a signal joins a co-active incident of its own family (cache + database are one family);
- a symptom (timeouts, 5xx) or an app bug joins the highest-priority co-active incident;
- a cause joins a co-active incident that has only symptoms so far (it explains them);
- any other cause starts its own incident (a DNS failure during a DB outage is a separate task).
Country shifts and RPS artifacts live in their own partitions.

An incident opens one bucket after it appears (time for the cause to show up) if it is sustained,
big or recurring. Long regressions stay open while their anchor template is above the level it had
before the incident, even when the adaptive baseline has stopped flagging it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from .detect.security import BotCfg, BotFeatures, is_bot_like
from .model import Signal
from .routing import Component, Router
from .timeutil import BUCKET

SEVERITY_ORDER = {"SEV-4": 0, "SEV-3": 1, "SEV-2": 2, "SEV-1": 3}
PARTITION_BY_FAMILY = {"seo": "seo", "data_quality": "data_quality"}


@dataclass
class Impact:
    lines: int = 0                 # error log lines of the incident's templates
    n5xx: int = 0
    clients: int = 0               # distinct user_id, or IP for anonymous requests
    users: int = 0                 # distinct logged-in users
    hosts: int = 0
    hosts_total: int = 0
    top_countries: list[tuple[str, int]] = field(default_factory=list)
    requests: float = 0.0          # requests served in the window (from rps)
    error_rate: float = 0.0        # 5xx lines / requests over the window
    peak_error_rate: float = 0.0   # worst 10-minute bucket: 5xx lines / requests
    requests_delta: float = 0.0    # traffic incidents: extra (+) or missing (-) requests


@dataclass(frozen=True)
class Fingerprint:
    component: str
    role: str
    templates: tuple[str, ...]
    country: str | None = None


@dataclass
class Incident:
    uid: str
    partition: str
    component: str
    role: str
    family: str
    start: datetime
    last_active: datetime
    created_at: datetime
    signals: dict[str, Signal] = field(default_factory=dict)
    status: str = "pending"        # pending | open | resolved | blip
    detected_at: datetime | None = None
    resolved_at: datetime | None = None
    severity: str = "SEV-3"
    reason: str = ""
    impact: Impact = field(default_factory=Impact)
    anchor: tuple[str, float] | None = None
    anchor_is_cause: bool = False
    bot: BotFeatures | None = None
    task_id: str | None = None
    slug: str | None = None           # file stem, fixed when the task is created
    considered: set[str] = field(default_factory=set, repr=False)

    @property
    def end(self) -> datetime:
        return max(s.end for s in self.signals.values())

    def log_signals(self) -> list[Signal]:
        return sorted((s for s in self.signals.values() if s.kind == "log_burst"), key=lambda s: -s.total)

    def template_ids(self) -> list[str]:
        seen: dict[str, float] = {}
        for s in self.log_signals():
            seen[s.key] = seen.get(s.key, 0.0) + s.total
        return [k for k, _ in sorted(seen.items(), key=lambda kv: -kv[1])]

    @property
    def volume(self) -> float:
        return sum(s.total for s in self.log_signals())

    def fingerprint(self) -> Fingerprint:
        country = next((s.key for s in self.signals.values() if s.kind == "country_shift"), None)
        return Fingerprint(self.component, self.role, tuple(self.template_ids()[:3]), country)


@dataclass
class Event:
    kind: str                      # opened | updated | resolved | blip
    incident: Incident
    at: datetime
    detail: str = ""


class Probe(Protocol):
    def impact(self, incident: Incident, now: datetime) -> Impact: ...
    def level(self, tpl_id: str, now: datetime) -> float: ...
    def bot(self, incident: Incident, now: datetime) -> BotFeatures | None: ...
    def typical(self, tpl_id: str, before: datetime) -> float: ...


@dataclass
class IncidentCfg:
    tol_buckets: int = 3
    close_after: int = 6
    close_after_sev1: int = 12
    grace_buckets: int = 1
    reassign_window: int = 3
    open_min_buckets: int = 2
    open_min_clients: int = 1000
    open_big_clients: int = 5000
    metric_min_buckets: int = 3
    recurring_count: int = 3
    recurring_window_h: int = 24
    recurring_min_clients: int = 200
    anchor_mult: float = 2.0
    anchor_min: float = 30.0
    country_gap: int = 36
    country_close_after: int = 36
    dq_open_count: int = 3
    dq_window_h: int = 24
    dq_close_after: int = 288
    impact_every: int = 3
    reopen_window_h: int = 72
    regression_h: int = 6
    cause_min_share: float = 0.05
    sev1_peak_rate: float = 0.01
    sev2_peak_rate: float = 0.001
    sev1_clients: int = 500_000
    sev2_clients: int = 50_000
    sev2_minutes: int = 60
    sev2_long_clients: int = 5000


def backed_by_new_signature(incident: Incident, router: Router) -> bool:
    """The incident's own component shows a cause template never seen before (a new failure mode)."""
    return any(s.attrs.get("new_template") and router.component_of(s).kind == "cause"
               and router.same_problem(router.component_of(s).name, incident.component)
               for s in incident.log_signals())


def signal_key(s: Signal) -> str:
    return f"{s.kind}:{s.key}:{s.start:%Y%m%d%H%M}"


class IncidentBook:
    def __init__(self, router: Router, probe: Probe, cfg: IncidentCfg | None = None, bot_cfg: BotCfg | None = None):
        self.router, self.probe, self.cfg, self.bot_cfg = router, probe, cfg or IncidentCfg(), bot_cfg or BotCfg()
        self.incidents: list[Incident] = []
        self.owner: dict[str, Incident] = {}
        self._elevated: dict[tuple[str, datetime], bool] = {}

    # --- public -------------------------------------------------------------------------------

    def step(self, signals: list[Signal], now: datetime) -> list[Event]:
        events: list[Event] = []
        causes_first = sorted(signals, key=lambda x: (x.start, self.router.component_of(x).kind != "cause", x.kind))
        for s in causes_first:
            key = signal_key(s)
            incident = self.owner.get(key)
            if incident is None:
                component = self.router.component_of(s)
                incident = (self._attach(s, component, now) or self._revive(s, component, now, events)
                            or self._create(s, component, now))
                self.owner[key] = incident
            incident.signals[key] = s
            incident.last_active = max(incident.last_active, s.end)
            if incident.status == "pending":
                self._compose(incident)
            elif (key not in incident.considered and self._can_reassign(incident, now)
                  and self.router.component_of(s).kind == "cause" and (s.attrs.get("new_template") or s.end > s.start)):
                incident.considered.add(key)  # a cause may reassign once it is new or lasting, not on every tick
                before = incident.role
                self._compose(incident)
                if incident.role != before:
                    events.append(Event("updated", incident, now, f"переназначено: {before} → {incident.role}"))
        for incident in [i for i in self.incidents if i.status in ("pending", "open")]:
            events += self._advance(incident, now)
        events += self._reopen(now)
        return events

    def _revive(self, s: Signal, component: Component, now: datetime, events: list[Event]) -> Incident | None:
        """The same cause template bursting again soon after its incident resolved reopens that incident."""
        window = timedelta(hours=self.cfg.reopen_window_h)
        for incident in reversed(self.incidents):
            if (self._is_regression(incident) and incident.anchor[0] == s.key and component.kind == "cause"
                    and now - incident.resolved_at <= window and self._anchor_elevated(incident, now)):
                incident.status, incident.resolved_at = "open", None
                events.append(Event("reopened", incident, now))
                return incident
        return None

    def _is_regression(self, incident: Incident) -> bool:
        """A resolved, long-running incident led by a cause template: worth watching for a comeback."""
        return (incident.status == "resolved" and incident.partition == "ops" and incident.anchor_is_cause
                and incident.anchor is not None
                and incident.resolved_at - incident.start >= timedelta(hours=self.cfg.regression_h))

    def _reopen(self, now: datetime) -> list[Event]:
        """A resolved regression whose cause template climbs back above its pre-incident level is the same
        incident, even though the adaptive baseline no longer flags it."""
        events: list[Event] = []
        if now.minute % 30:  # every 30 minutes is enough for days-long regressions
            return events
        window = timedelta(hours=self.cfg.reopen_window_h)
        active = [i.component for i in self.active("ops")]
        resolved = [i for i in self.incidents if self._is_regression(i)]
        for incident in sorted(resolved, key=lambda i: i.resolved_at, reverse=True):
            if (not any(self.router.same_problem(incident.component, c) for c in active)
                    and now - incident.resolved_at <= window and self._anchor_elevated(incident, now)):
                active.append(incident.component)
                incident.status, incident.resolved_at, incident.last_active = "open", None, now
                events.append(Event("reopened", incident, now))
        return events

    def active(self, partition: str | None = None) -> list[Incident]:
        return [i for i in self.incidents if i.status in ("pending", "open")
                and (partition is None or i.partition == partition)]

    # --- attach / create ----------------------------------------------------------------------

    def _attach(self, s: Signal, component: Component, now: datetime) -> Incident | None:
        partition = PARTITION_BY_FAMILY.get(component.family, "ops")
        if partition == "seo":
            if s.attrs.get("direction") == "down":  # a country losing traffic during an outage is a symptom
                outage = [i for i in self.active("ops") if i.status == "open" and i.severity in ("SEV-1", "SEV-2")
                          and self._coactive(i, s, now)]
                if outage:
                    return max(outage, key=lambda i: (SEVERITY_ORDER[i.severity], i.volume))
            return next((i for i in self.active("seo") if any(
                x.kind == "country_shift" and x.key == s.key and x.attrs.get("direction") == s.attrs.get("direction")
                for x in i.signals.values()) and s.start - i.last_active <= self.cfg.country_gap * BUCKET), None)
        if partition == "data_quality":
            return next(iter(self.active("data_quality")), None)
        same = [i for i in self.active("ops")
                if self.router.same_problem(i.component, component.name) and self._coactive(i, s, now, extend=True)]
        if same:
            return max(same, key=lambda i: i.volume)
        candidates = [i for i in self.active("ops") if self._coactive(i, s, now)]
        if not candidates:
            return None
        if component.kind == "symptom" or component.name == "app_bug":
            return max(candidates, key=lambda i: (self.router.priority(i.family), i.volume))
        symptom_only = [i for i in candidates if self.router.get(i.component).kind == "symptom"
                        and (i.status == "pending" or self._can_reassign(i, now))]
        return max(symptom_only, key=lambda i: i.volume) if symptom_only else None

    def _can_reassign(self, incident: Incident, now: datetime) -> bool:
        return (incident.status == "open" and incident.component != "abuse" and incident.partition == "ops"
                and now - incident.detected_at <= self.cfg.reassign_window * BUCKET)

    def _create(self, s: Signal, component: Component, now: datetime) -> Incident:
        incident = Incident(uid=f"{component.name}-{s.start:%Y%m%d-%H%M}-{s.key[:6]}",
                            partition=PARTITION_BY_FAMILY.get(component.family, "ops"), component=component.name,
                            role=component.role, family=component.family, start=s.start, last_active=s.end,
                            created_at=now)
        self.incidents.append(incident)
        if (incident.partition == "ops" and component.kind == "cause"
                and (s.attrs.get("new_template") or s.end > s.start)):
            self._reclaim(incident, s, now)  # only a new or lasting cause; a familiar blip explains nothing
        return incident

    def _reclaim(self, incident: Incident, cause: Signal, now: datetime) -> None:
        """Symptoms often show up a bucket before their cause; when the cause arrives, take the symptoms that
        began around it away from a lower-priority incident they were parked in."""
        tol = self.cfg.tol_buckets * BUCKET
        mine = self.router.priority(incident.family)
        for other in self.active("ops"):
            if other is incident or self.router.priority(other.family) >= mine:
                continue
            for key, s in list(other.signals.items()):
                if (self.router.component_of(s).kind == "symptom" and s.start >= cause.start - tol
                        and s.end >= now - tol and len(other.signals) > 1):
                    del other.signals[key]
                    incident.signals[key] = s
                    incident.last_active = max(incident.last_active, s.end)
                    incident.start = min(incident.start, s.start)
                    self.owner[key] = incident

    def _compose(self, incident: Incident) -> None:
        """Primary component: the highest-priority cause, else the highest-priority symptom."""
        if incident.partition != "ops":
            return
        comps = {self.router.component_of(s).name: self.router.component_of(s) for s in incident.signals.values()}
        total = incident.volume or 1.0

        def strong(s: Signal) -> bool:
            """A cause leads only if it is new, sizeable or lasting; a familiar one-bucket blip is context."""
            return (s.kind != "log_burst" or bool(s.attrs.get("new_template"))
                    or s.total / total >= self.cfg.cause_min_share or s.end > s.start)

        causes = list({self.router.component_of(s).name: self.router.component_of(s)
                       for s in incident.signals.values()
                       if self.router.component_of(s).kind == "cause" and strong(s)}.values())
        pool = causes or [c for c in comps.values() if c.kind == "symptom"] or list(comps.values())
        volume = {name: sum(s.total for s in incident.signals.values()
                            if s.kind == "log_burst" and self.router.component_of(s).name == name) for name in comps}
        primary = max(pool, key=lambda c: (self.router.priority(c.family), volume[c.name]))
        under_load = any((s.kind == "rps_shift" and s.value > s.baseline) or s.kind == "cpu_high"
                         for s in incident.signals.values())
        if not causes and primary.family in ("upstream", "app") and under_load:
            primary = self.router.get("capacity")
        incident.component, incident.role, incident.family = primary.name, primary.role, primary.family
        anchors = [s for s in incident.log_signals() if self.router.component_of(s).kind == "cause"] \
            or incident.log_signals()
        if anchors and incident.status == "pending":  # fixed at open (see _open)
            a = anchors[0]
            incident.anchor = (a.key, a.points[0].baseline if a.points else a.baseline)
            incident.anchor_is_cause = self.router.component_of(a).kind == "cause"

    # --- lifecycle ----------------------------------------------------------------------------

    def _advance(self, incident: Incident, now: datetime) -> list[Event]:
        if incident.status == "pending":
            if self._qualifies(incident, now):
                self._open(incident, now)
                return [Event("opened", incident, now, incident.reason)]
            if self._inactive(incident, now):
                incident.status, incident.resolved_at = "blip", now
                return [Event("blip", incident, now)]
            return []
        if self._inactive(incident, now):
            incident.impact = self.probe.impact(incident, now)
            incident.severity = max(incident.severity, self._severity(incident), key=SEVERITY_ORDER.get)
            incident.status, incident.resolved_at = "resolved", now
            return [Event("resolved", incident, now)]
        ticks = int((now - incident.detected_at) / BUCKET)
        every = self.cfg.impact_every if ticks <= 36 else 36  # long incidents: severity is settled after 6 h
        if incident.partition == "ops" and ticks and ticks % every == 0:
            incident.impact = self.probe.impact(incident, now)
            severity = self._severity(incident)
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[incident.severity]:
                detail = f"{incident.severity} → {severity}"
                incident.severity = severity
                return [Event("updated", incident, now, detail)]
        return []

    def _qualifies(self, incident: Incident, now: datetime) -> bool:
        cfg = self.cfg
        if incident.partition == "seo":
            incident.reason = "country shift"
            return True
        if incident.partition == "data_quality":
            recent = [s for s in incident.signals.values() if now - s.start <= timedelta(hours=cfg.dq_window_h)]
            incident.reason = "repeating metric artifact"
            return len(recent) >= cfg.dq_open_count
        if now - incident.created_at < cfg.grace_buckets * BUCKET:
            return False
        incident.impact = self.probe.impact(incident, now)
        buckets = int((incident.end - incident.start) / BUCKET) + 1
        if not incident.log_signals():  # metrics only (traffic, CPU): no clients to count, judge by duration
            incident.reason = "metric deviation"
            return buckets >= cfg.metric_min_buckets
        if incident.impact.clients >= cfg.open_big_clients:
            incident.reason = "high impact"
        elif buckets >= cfg.open_min_buckets and incident.impact.clients >= cfg.open_min_clients:
            incident.reason = "sustained"
        elif (incident.impact.clients >= cfg.recurring_min_clients
              and self._previous_blips(incident, now) >= cfg.recurring_count - 1):
            incident.reason = "recurring"
        else:
            return False
        return True

    def _open(self, incident: Incident, now: datetime) -> None:
        incident.status, incident.detected_at = "open", now
        if incident.anchor:
            tpl_id, base = incident.anchor
            incident.anchor = (tpl_id, min(base, self.probe.typical(tpl_id, incident.start - BUCKET)))
        if incident.partition == "ops":
            incident.bot = self.probe.bot(incident, now)
            if incident.bot and is_bot_like(incident.bot, self.bot_cfg)[0]:
                abuse = self.router.get("abuse")
                incident.component, incident.role, incident.family = abuse.name, abuse.role, abuse.family
        incident.severity = self._severity(incident)

    def _previous_blips(self, incident: Incident, now: datetime) -> int:
        fp = incident.fingerprint()
        window = timedelta(hours=self.cfg.recurring_window_h)
        return sum(1 for i in self.incidents if i.status == "blip" and now - i.start <= window
                   and i.fingerprint() == fp)

    def _severity(self, incident: Incident) -> str:
        cfg, imp = self.cfg, incident.impact
        if incident.partition == "data_quality":
            return "SEV-4"
        if incident.partition == "seo":
            return "SEV-3"
        floor = "SEV-2" if incident.component == "abuse" else "SEV-3"
        minutes = (incident.end - incident.start) / timedelta(minutes=1) + 10
        if (imp.peak_error_rate >= cfg.sev1_peak_rate or imp.clients >= cfg.sev1_clients
                or any(s.kind == "cpu_high" for s in incident.signals.values())):
            return "SEV-1"
        if (imp.peak_error_rate >= cfg.sev2_peak_rate or imp.clients >= cfg.sev2_clients
                or (minutes >= cfg.sev2_minutes and imp.clients >= cfg.sev2_long_clients)):
            return "SEV-2"
        return floor

    # --- activity -----------------------------------------------------------------------------

    def _active_until(self, incident: Incident, now: datetime) -> datetime:
        return now if self._anchor_elevated(incident, now) else incident.last_active

    def _coactive(self, incident: Incident, s: Signal, now: datetime, extend: bool = False) -> bool:
        """`s` overlaps the incident while it is still open. Only signals of the same problem may use
        the anchor extension, so a days-long regression does not collect unrelated symptoms."""
        until = self._active_until(incident, now) if extend else incident.last_active
        close = self.cfg.close_after_sev1 if incident.severity == "SEV-1" else self.cfg.close_after
        if self.router.get(incident.component).kind == "symptom":
            close = self.cfg.tol_buckets  # only a cause holds an incident together across pauses
        return (s.start <= until + close * BUCKET
                and s.end >= incident.start - self.cfg.tol_buckets * BUCKET)

    def _inactive(self, incident: Incident, now: datetime) -> bool:
        close = {"seo": self.cfg.country_close_after, "data_quality": self.cfg.dq_close_after}.get(
            incident.partition, self.cfg.close_after_sev1 if incident.severity == "SEV-1" else self.cfg.close_after)
        return now - self._active_until(incident, now) >= close * BUCKET

    def _anchor_elevated(self, incident: Incident, now: datetime) -> bool:
        if incident.anchor is None or incident.partition != "ops":
            return False
        key = (incident.uid, now)
        if key not in self._elevated:
            tpl_id, base = incident.anchor
            threshold = max(self.cfg.anchor_mult * base, base + self.cfg.anchor_min)
            self._elevated[key] = self.probe.level(tpl_id, now) >= threshold
        return self._elevated[key]
