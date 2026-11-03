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


def vote(rules: str, analyst: str | None, verdict: Verdict | None, rules_strong: bool = False) -> tuple[str, bool, str]:
    """Return (assignee, needs_human, note).

    `rules_strong`: the rules' choice rests on a cause signature never seen before (a new failure mode).
    Models may disagree with it, but not overrule it silently: the rules' owner keeps the task and a person decides.
    """
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
    if rules_strong and role != rules:
        notes.append(f"правила опираются на новую сигнатуру-причину и назначили {rules}; модели предлагали {role} — "
                     "проверьте назначение")
        role, needs_human = rules, True
    if verdict and not verdict.is_anomaly:
        needs_human = True
        notes.append(f"арбитр сомневается, что это аномалия: {verdict.reason}")
    return role, needs_human, "; ".join(notes)
