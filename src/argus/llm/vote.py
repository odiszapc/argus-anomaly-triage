"""Who gets the task: routing rules, the analyst and the arbiter vote; a split goes to a human."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


@dataclass
class Verdict:
    is_anomaly: bool
    assignee: str
    severity: str
    confidence: float
    reason: str
    model: str = ""


def vote(rules: str, analyst: str | None, verdict: Verdict | None) -> tuple[str, bool, str]:
    """Return (assignee, needs_human, note)."""
    ballots = {"правила": rules}
    if analyst:
        ballots["аналитик"] = analyst
    if verdict:
        ballots["арбитр"] = verdict.assignee
    role, count = Counter(ballots.values()).most_common(1)[0]
    needs_human, notes = False, []
    if count < 2 and len(ballots) > 1:
        role, needs_human = analyst or rules, True
        notes.append("голоса разошлись: " + ", ".join(f"{k} — {v}" for k, v in ballots.items()))
    if verdict and not verdict.is_anomaly:
        needs_human = True
        notes.append(f"арбитр сомневается, что это аномалия: {verdict.reason}")
    return role, needs_human, "; ".join(notes)
