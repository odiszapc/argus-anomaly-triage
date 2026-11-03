"""How well did a run do against the labelled incidents (evals/gold.yaml)?

Recall, assignee accuracy, time to detect, whether repeats landed in the right task, tasks that match no
label (false positives or simply unlabelled), and the hit rate of predictions. `make eval` prints it, so an
agent changing a threshold sees the effect before committing.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from .timeutil import BUCKET, parse_ts

SLACK = timedelta(minutes=30)


@dataclass
class Gold:
    id: str
    name: str
    start: datetime
    end: datetime
    role: str
    severity: str | None = None
    repeat_of: str | None = None
    kind: str = "incident"
    component: str | None = None   # when set, only detections of this component match
    country: str | None = None


@dataclass
class Detection:
    task: str
    role: str
    start: datetime          # first anomalous minute (bucket label - 10 min)
    detected_at: datetime
    end: datetime
    parent_task: str | None  # set when filed as a repeat
    component: str | None = None
    country: str | None = None


@dataclass
class Row:
    gold: str
    name: str
    role: str
    task: str | None = None
    found_role: str | None = None
    ttd_min: int | None = None
    repeat_ok: bool | None = None

    @property
    def role_ok(self) -> bool:
        return self.found_role == self.role


@dataclass
class EvalResult:
    rows: list[Row]
    recall: float
    role_accuracy: float
    median_ttd_min: float | None
    tasks: int
    unlabelled: list[str]
    predictions: list[dict] = field(default_factory=list)

    @property
    def prediction_hits(self) -> int:
        return sum(1 for p in self.predictions if p["hit"])


def load_gold(path: Path) -> list[Gold]:
    raw = yaml.safe_load(Path(path).read_text())["incidents"]
    return [Gold(g["id"], g["name"], parse_ts(str(g["start"])), parse_ts(str(g["end"])), g["role"],
                 g.get("severity"), g.get("repeat_of"), g.get("kind", "incident"), g.get("component"),
                 g.get("country")) for g in raw]


def detections_from(memory) -> list[Detection]:
    by_uid = {i.uid: i for i in memory.incidents}
    out = []
    for rec in memory.tasks.values():
        inc = by_uid[rec.incident_uid]
        out.append(Detection(rec.task_id, rec.triage.assignee, inc.start - BUCKET, rec.opened_at,
                             inc.resolved_at or inc.end, None, inc.component, inc.fingerprint().country))
        for r in rec.repeats:
            rep = by_uid.get(r["uid"])
            if rep:
                out.append(Detection(rec.task_id, rec.triage.assignee, rep.start - BUCKET, rep.detected_at,
                                     rep.resolved_at or rep.end, rec.task_id, rep.component, rep.fingerprint().country))
    return out


def evaluate(gold: list[Gold], detections: list[Detection], predictions: list) -> EvalResult:
    rows: dict[str, Row] = {}
    matched: set[str] = set()
    for g in gold:
        row = Row(g.id, g.name, g.role)
        cands = [d for d in detections if d.start <= g.end + SLACK and d.end >= g.start - SLACK
                 and (g.component is None or d.component == g.component)
                 and (g.country is None or d.country == g.country)
                 and (g.kind == "data_quality" or d.component != "observability")]
        if cands:
            best = sorted(cands, key=lambda d: (d.role != g.role, d.detected_at))[0]
            matched.add(best.task)
            row.task, row.found_role = best.task, best.role
            row.ttd_min = max(0, int((best.detected_at - g.start).total_seconds() // 60))
            if g.repeat_of and g.repeat_of in rows:
                row.repeat_ok = best.task == rows[g.repeat_of].task
        elif g.repeat_of:
            row.repeat_ok = False
        rows[g.id] = row
    found = [r for r in rows.values() if r.task]
    tasks = {d.task for d in detections}
    ttds = [r.ttd_min for r in found if r.ttd_min is not None]
    preds = []
    for p in predictions:
        hit = next((d for d in detections if d.role == p.role and p.window_start <= d.start + BUCKET <= p.window_end
                    and d.start + BUCKET > p.at), None)
        preds.append({"target": p.target, "at": p.at, "window": (p.window_start, p.window_end), "hit": hit is not None,
                      "lead_min": int((hit.start - p.at).total_seconds() // 60) if hit else None,
                      "hit_task": hit.task if hit else None})
    return EvalResult(list(rows.values()), len(found) / len(gold) if gold else 0.0,
                      sum(r.role_ok for r in found) / len(found) if found else 0.0,
                      statistics.median(ttds) if ttds else None, len(tasks), sorted(tasks - matched), preds)


def render(result: EvalResult) -> str:
    lines = ["| Эталон | Что | Задача | Роль ожид./найдена | TTD, мин | Повтор в той же задаче |",
             "|---|---|---|---|---|---|"]
    for r in result.rows:
        role = f"{r.role} / {r.found_role or '—'}" + (" ✓" if r.task and r.role_ok else (" ✗" if r.task else ""))
        rep = {True: "да", False: "нет", None: ""}[r.repeat_ok]
        lines.append(f"| {r.gold} | {r.name} | {r.task or 'не найден'} | {role} | "
                     f"{'' if r.ttd_min is None else r.ttd_min} | {rep} |")
    lines += ["", f"- Найдено эталонных инцидентов: **{sum(1 for r in result.rows if r.task)} из {len(result.rows)}** "
                  f"(recall {result.recall:.0%}), исполнитель верный в {result.role_accuracy:.0%} найденных",
              f"- Медианное время до оповещения: {result.median_ttd_min} мин",
              f"- Задач всего: {result.tasks}; без эталонной метки: {len(result.unlabelled)} "
              f"({', '.join(result.unlabelled) or '—'})",
              f"- Прогнозы: {result.prediction_hits} из {len(result.predictions)} сбылись"]
    for p in result.predictions:
        lines.append(f"  - {p['target']} {p['at']:%d.%m %H:%M} → окно {p['window'][0]:%d.%m %H:%M}–"
                     f"{p['window'][1]:%H:%M}: " + (f"сбылся ({p['hit_task']}, за {p['lead_min']} мин)" if p["hit"]
                                                     else "не сбылся"))
    return "\n".join(lines)
