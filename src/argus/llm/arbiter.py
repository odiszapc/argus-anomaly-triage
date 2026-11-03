"""Arbiter: a model from another family re-judges the alert from facts only ("blind" evidence: no rules
opinion, no analyst text), then rules + analyst + arbiter vote on the owner. A split or an arbiter who
thinks it is noise marks the task `needs-human`."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from ..correlate import Incident
from ..evidence import build_evidence
from ..model import ROLES
from ..routing import Router
from ..store import Store
from ..triage import Triage
from .analyst import ollama_json, ollama_url, run_claude_agent
from .vote import Verdict, vote

SYSTEM = (Path(__file__).parent / "prompts" / "arbiter.md").read_text()
SEVERITIES = ["SEV-1", "SEV-2", "SEV-3", "SEV-4"]
VERDICT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["is_anomaly", "assignee", "severity", "confidence", "reason"],
    "properties": {"is_anomaly": {"type": "boolean"}, "assignee": {"type": "string", "enum": list(ROLES)},
                   "severity": {"type": "string", "enum": SEVERITIES}, "confidence": {"type": "number"},
                   "reason": {"type": "string"}},
}


def verdict_from(out: dict, model: str) -> Verdict:
    assignee = out.get("assignee") if out.get("assignee") in ROLES else None
    if assignee is None:
        raise ValueError(f"arbiter returned an unknown role: {out.get('assignee')!r}")
    return Verdict(bool(out.get("is_anomaly", True)), assignee,
                   out.get("severity") if out.get("severity") in SEVERITIES else "SEV-3",
                   float(out.get("confidence", 0.5)), str(out.get("reason", "")).strip(), model)


class BaseArbiter:
    model = ""

    def judge(self, evidence: dict) -> Verdict:
        raise NotImplementedError

    def review(self, incident: Incident, triage: Triage, store: Store, now: datetime, router: Router) -> Verdict | None:
        try:
            verdict = self.judge(build_evidence(incident, store, router, now, blind=True))
        except Exception as e:  # noqa: BLE001 — a dead arbiter must not block the alert
            triage.arbiter_note = (triage.arbiter_note + " " if triage.arbiter_note else "") + \
                f"Арбитр ({self.model}) недоступен: {str(e)[:120]}."
            return None
        analyst = triage.assignee if triage.source != "rules" else None
        role, needs_human, note = vote(incident.role, analyst, verdict)
        triage.votes["arbiter"] = verdict.assignee
        triage.assignee, triage.needs_human = role, needs_human
        if not note:
            note = (f"Арбитр ({verdict.model}) согласен: {verdict.reason}" if verdict.assignee == role else
                    f"Арбитр ({verdict.model}) предлагал {verdict.assignee}: {verdict.reason} Большинство голосов — {role}.")
        triage.arbiter_note = note
        incident.role = role
        return verdict


class OllamaArbiter(BaseArbiter):
    def __init__(self, model: str = "qwen3:14b", host: str | None = None, think: bool = False):
        self.model, self.host, self.think = model, ollama_url(host or os.environ.get("OLLAMA_HOST")), think

    def judge(self, evidence: dict) -> Verdict:
        out = ollama_json(self.host, self.model, SYSTEM, json.dumps(evidence, ensure_ascii=False, default=str),
                          VERDICT_SCHEMA, think=self.think)
        return verdict_from(out, self.model)


class ClaudeArbiter(BaseArbiter):
    """Used when no local model is available: a different Claude model, no tools, one answer."""

    def __init__(self, model: str = "claude-sonnet-5-5"):
        self.model = model

    def judge(self, evidence: dict) -> Verdict:
        result = run_claude_agent(system=SYSTEM, prompt=json.dumps(evidence, ensure_ascii=False, default=str),
                                  schema=VERDICT_SCHEMA, model=self.model, effort="low", max_turns=2,
                                  budget_usd=0.5)
        return verdict_from(result.output, self.model)
