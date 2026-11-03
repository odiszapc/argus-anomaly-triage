"""Predictions for #app-alert-predictions.

Recurrence watch: a data-store or infrastructure incident that began under load and was "fixed" by
the load going away tends to come back at the next ramp (in this data: Valkey 02.09 → 03.09 morning,
MongoDB 25.08 → 26.08 morning). When such a SEV-1/2 incident resolves, the predictor forecasts RPS
for the next 24 hours from the same time of day on previous days and warns before the forecast
climbs back to the level at which the incident began.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from .correlate import Incident
from .render.fmt import human
from .routing import Router
from .timeutil import BUCKET, sql_ts


@dataclass
class Prediction:
    kind: str
    target: str            # task id the prediction is about
    component: str
    role: str
    at: datetime
    window_start: datetime
    window_end: datetime
    text: str
    detail: dict = field(default_factory=dict)

    def payload(self, channel: str) -> dict:
        header = f"🔮 Прогноз: риск повтора {self.target} в {self.window_start:%d.%m %H:%M}–{self.window_end:%H:%M} UTC"
        return {"channel": channel, "text": f"{header} — {self.role}", "unfurl_links": False, "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": header[:150], "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": self.text}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text":
                f"Кому: {self.role} · основание: прогноз RPS по тем же часам прошлых дней"}]}]}


class Predictor:
    def __init__(self, cfg: dict, router: Router, store):
        self.router, self.store = router, store
        self.families = set(cfg.get("families", ["data_store", "infra"]))
        self.severities = set(cfg.get("severities", ["SEV-1", "SEV-2"]))
        self.horizon = timedelta(hours=float(cfg.get("horizon_h", 24)))
        self.min_lead = timedelta(hours=float(cfg.get("min_lead_h", 1)))
        self.ratio = float(cfg.get("trigger_ratio", 0.95))
        self.lead = timedelta(minutes=float(cfg.get("window_before_min", 60)))
        self.done: set[str] = set()
        self.last_for_target: dict[str, datetime] = {}

    def tick(self, now: datetime, signals, book) -> list[Prediction]:
        out = []
        for incident in book.incidents:
            if (incident.status == "resolved" and incident.resolved_at == now and incident.uid not in self.done
                    and incident.severity in self.severities and incident.family in self.families):
                self.done.add(incident.uid)
                target = incident.task_id or incident.uid
                if now - self.last_for_target.get(target, datetime.min) < timedelta(hours=24):
                    continue  # one warning per task per day
                prediction = self._recurrence(incident, now)
                if prediction:
                    self.last_for_target[target] = now
                    out.append(prediction)
        return out

    def _rps(self, now: datetime) -> pd.Series:
        df = self.store.df(f"SELECT ts, value FROM metric_rps WHERE ts <= {sql_ts(now)} ORDER BY ts")
        return df.set_index("ts")["value"].astype(float)

    def _recurrence(self, incident: Incident, now: datetime) -> Prediction | None:
        rps = self._rps(now)
        began = rps[(rps.index >= incident.start - BUCKET) & (rps.index <= incident.start + 2 * BUCKET)]
        if began.empty:
            return None
        trigger = float(began.median())
        day = rps[rps.index > now - timedelta(hours=24)]
        if day.empty or trigger < float(day.median()):
            return None  # began under low load: a load ramp is not the suspect
        steps = pd.date_range(now + BUCKET, now + self.horizon, freq="10min")
        forecast = []
        for t in steps:
            past = [rps.get(t - timedelta(days=d)) for d in range(1, 8)]
            past = [v for v in past if v is not None and not np.isnan(v)]
            forecast.append(float(np.median(past)) if past else np.nan)
        fc = pd.Series(forecast, index=steps)
        below_seen = False
        for t, v in fc.items():
            if np.isnan(v):
                continue
            if v < self.ratio * trigger:
                below_seen = True
            elif below_seen and t - now >= self.min_lead:
                start, end = t.to_pydatetime() - self.lead, t.to_pydatetime() + timedelta(hours=3)
                comp = self.router.get(incident.component)
                text = (f"*{incident.task_id}* ({comp.title}) закрыт в {now:%d.%m %H:%M}, но начался при нагрузке "
                        f"≈{human(trigger)} RPS. По тем же часам прошлых дней нагрузка снова дойдёт до этого уровня "
                        f"к *{t:%d.%m %H:%M} UTC* (прогноз ≈{human(v)} RPS). Если причина не устранена, ждём повтора. "
                        f"До {start:%H:%M} стоит проверить состояние {comp.title.lower()} и запас ёмкости.")
                return Prediction("recurrence", incident.task_id or incident.uid, incident.component, incident.role,
                                  now, start, end, text, {"trigger_rps": trigger, "forecast_rps": v,
                                                          "ramp_at": t.to_pydatetime()})
        return None
