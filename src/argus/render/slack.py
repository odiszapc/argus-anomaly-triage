"""Slack Web API payloads (Block Kit), recorded to slack-log.json instead of being sent.

Each entry is exactly what would be POSTed: `method` (chat.postMessage / chat.update) and `payload`.
Follow-ups go to the alert's thread (`thread_ts`), so one incident is one conversation in #app-alerts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..correlate import Incident
from ..triage import Triage
from .fmt import human, pct

SEV_EMOJI = {"SEV-1": "🔴", "SEV-2": "🟠", "SEV-3": "🟡", "SEV-4": "⚪"}


def _text(s: str, limit: int = 2900) -> str:
    return s if len(s) <= limit else s[: limit - 1] + "…"


def alert_payload(incident: Incident, triage: Triage, channel: str, task_url: str, pm_url: str | None = None,
                  mention: str | None = None, resolved: bool = False) -> dict:
    emoji = "✅" if resolved else SEV_EMOJI.get(incident.severity, "🟡")
    header = f"{emoji} {incident.severity} · {triage.title}"
    if len(header) > 150:
        header = header[:149] + "…"
    ttd = int((incident.detected_at - incident.start).total_seconds() // 60) + 10
    impact = f"≈{human(incident.impact.clients)} клиентов" if incident.impact.clients else "—"
    if incident.impact.peak_error_rate:
        impact += f", пик ошибок {pct(incident.impact.peak_error_rate)}"
    who = f"{mention} ({triage.assignee})" if mention else triage.assignee
    fields = [
        {"type": "mrkdwn", "text": f"*Исполнитель*\n{who}"},
        {"type": "mrkdwn", "text": f"*Затронуто*\n{impact}"},
        {"type": "mrkdwn", "text": f"*Начало*\n{incident.start:%d.%m %H:%M} UTC"},
        {"type": "mrkdwn", "text": f"*Обнаружено*\nчерез {ttd} мин" + (
            f"\n*Закрыт* {incident.resolved_at:%d.%m %H:%M}" if resolved and incident.resolved_at else "")},
    ]
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header, "emoji": True}},
        {"type": "section", "fields": fields},
        {"type": "section", "text": {"type": "mrkdwn", "text": _text(triage.summary)}},
    ]
    if triage.hypotheses:
        h = triage.hypotheses[0]
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": _text(f"*Гипотеза:* {h.cause} _({h.confidence})_")}]})
    votes = " · ".join(f"{k}: {v}" for k, v in triage.votes.items())
    note = f"⚠️ *Нужно решение человека:* {triage.arbiter_note}" if triage.needs_human else f"Голоса — {votes}"
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _text(note)}]})
    buttons = [{"type": "button", "text": {"type": "plain_text", "text": f"Задача {incident.task_id}"}, "url": task_url}]
    if pm_url:
        buttons.append({"type": "button", "text": {"type": "plain_text", "text": "Post-mortem"}, "url": pm_url})
    blocks.append({"type": "actions", "elements": buttons})
    return {"channel": channel, "text": f"{header} — {triage.assignee}", "blocks": blocks,
            "unfurl_links": False, "unfurl_media": False}


def note_payload(channel: str, text: str) -> dict:
    return {"channel": channel, "text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn",
                                                                                      "text": _text(text)}}]}


def _epoch(at: datetime) -> int:
    return int(at.replace(tzinfo=timezone.utc).timestamp())


class SlackLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.entries: list[dict] = json.loads(self.path.read_text()) if self.path.exists() else []

    def _append(self, method: str, payload: dict, at: datetime, meta: dict) -> str:
        ts = f"{_epoch(at)}.{len(self.entries) + 1:06d}"
        self.entries.append({"ts": ts, "method": method, "payload": payload,
                             "meta": {**meta, "at": at.strftime("%Y-%m-%dT%H:%M:%SZ")}})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, ensure_ascii=False, indent=2))
        return ts

    def post(self, payload: dict, at: datetime, meta: dict) -> str:
        return self._append("chat.postMessage", payload, at, meta)

    def reply(self, thread_ts: str, payload: dict, at: datetime, meta: dict, broadcast: bool = False) -> str:
        return self._append("chat.postMessage", {**payload, "thread_ts": thread_ts, "reply_broadcast": broadcast},
                            at, meta)

    def update(self, ts: str, payload: dict, at: datetime, meta: dict) -> str:
        return self._append("chat.update", {**payload, "ts": ts}, at, meta)
