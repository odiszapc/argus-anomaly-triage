"""LLM triage analyst.

Claude runs as an agent (Claude Agent SDK) with one in-process tool, read-only SQL, and must answer
in a JSON schema. Code then checks every number it wrote against the evidence and its own query
results; unsupported numbers trigger one repair turn, and whatever is still unsupported is flagged
in the task. Any failure falls back to the rules-only triage, so an alert is never lost to an LLM
error.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import httpx

from ..correlate import Incident
from ..evidence import build_evidence
from ..model import ROLES
from ..routing import Router
from ..store import Store
from ..triage import IMPACT_NOTE, Hypothesis, Triage, fallback_triage
from .tools import SCHEMA_DOC, run_sql
from .verify import known_numbers, verify_numbers

PROMPTS = Path(__file__).parent / "prompts"
CONFIDENCE = ["высокая", "средняя", "низкая"]

TRIAGE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["title", "summary", "symptoms", "hypotheses", "assignee", "assignee_reason", "next_steps",
                 "impact_note"],
    "properties": {
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "symptoms": {"type": "array", "items": {"type": "string"}},
        "hypotheses": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["cause", "evidence", "confidence"],
            "properties": {"cause": {"type": "string"}, "evidence": {"type": "string"},
                           "confidence": {"type": "string", "enum": CONFIDENCE}}}},
        "assignee": {"type": "string", "enum": list(ROLES)},
        "assignee_reason": {"type": "string"},
        "next_steps": {"type": "array", "items": {"type": "string"}},
        "impact_note": {"type": "string"},
    },
}

REPAIR = ("Код не нашёл в данных подтверждения для этих чисел: {numbers}. Проверьте их запросом sql или уберите "
          "из текста, затем верните исправленный JSON целиком.")


def triage_from_output(out: dict, rules_role: str) -> Triage:
    hyps = [Hypothesis(str(h.get("cause", "")), str(h.get("evidence", "")),
                       h.get("confidence") if h.get("confidence") in CONFIDENCE else "низкая")
            for h in out.get("hypotheses", []) if isinstance(h, dict)]
    assignee = out.get("assignee") if out.get("assignee") in ROLES else rules_role
    return Triage(title=str(out.get("title", "")).strip()[:140], summary=str(out.get("summary", "")).strip(),
                  symptoms=[str(s) for s in out.get("symptoms", [])][:8], hypotheses=hyps[:5], assignee=assignee,
                  assignee_reason=str(out.get("assignee_reason", "")).strip(),
                  next_steps=[str(s) for s in out.get("next_steps", [])][:6],
                  impact_note=str(out.get("impact_note", "")).strip() or IMPACT_NOTE)


def _texts(t: Triage) -> list[str]:
    return [t.title, t.summary, t.assignee_reason, t.impact_note, *t.symptoms, *t.next_steps,
            *(h.cause + " " + h.evidence for h in t.hypotheses)]


@dataclass
class AgentResult:
    output: dict
    session_id: str | None
    cost_usd: float | None


def run_claude_agent(*, system: str, prompt: str, schema: dict, model: str, effort: str, max_turns: int,
                     budget_usd: float, sql: Callable[[str], str] | None = None,
                     resume: str | None = None) -> AgentResult:
    """One Claude Agent SDK session: our SQL tool only, no built-in tools, no user settings, JSON answer."""
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, create_sdk_mcp_server, query, tool

    servers, allowed = {}, []
    if sql is not None:
        @tool("sql", "Read-only DuckDB SQL over the logs and metrics that existed at alert time. "
              "At most 50 rows per call; aggregate instead of listing raw lines.\n" + SCHEMA_DOC, {"query": str})
        async def sql_tool(args):
            text = sql(args.get("query", ""))
            return {"content": [{"type": "text", "text": text}], "is_error": text.startswith("ERROR")}

        servers = {"argus": create_sdk_mcp_server("argus", tools=[sql_tool])}
        allowed = ["mcp__argus__sql"]
    options = ClaudeAgentOptions(
        model=model, effort=effort, max_turns=max_turns, max_budget_usd=budget_usd, system_prompt=system,
        tools=[], allowed_tools=allowed, mcp_servers=servers, setting_sources=[], skills=[], resume=resume,
        output_format={"type": "json_schema", "schema": schema}, cwd=tempfile.gettempdir(),
        env={"CLAUDECODE": ""})  # allows running from inside a Claude Code session

    async def go():
        last = None
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage):
                last = message
        return last

    result = asyncio.run(go())
    if result is None or result.is_error or not isinstance(result.structured_output, dict):
        detail = (result.errors or result.subtype) if result else "no result"
        raise RuntimeError(f"agent failed: {detail}")
    return AgentResult(result.structured_output, result.session_id, result.total_cost_usd)


class ClaudeAnalyst:
    name = "claude"

    def __init__(self, router: Router, model: str = "claude-opus-5-5", effort: str = "medium", max_turns: int = 10,
                 budget_usd: float = 2.0, runner: Callable[..., AgentResult] | None = None):
        self.router, self.model, self.effort, self.max_turns, self.budget = router, model, effort, max_turns, budget_usd
        self.runner = runner or run_claude_agent
        self.system = (PROMPTS / "analyst.md").read_text()
        self.cost_usd = 0.0

    def triage(self, incident: Incident, store: Store, now: datetime, related: list[dict] | None = None) -> Triage:
        try:
            return self._triage(incident, store, now, related)
        except Exception as e:  # noqa: BLE001 — any model/transport failure must not lose the alert
            rules = fallback_triage(incident, self.router)
            rules.arbiter_note = f"LLM-аналитик недоступен ({str(e)[:160]}); текст задачи собран правилами."
            return rules

    def _triage(self, incident: Incident, store: Store, now: datetime, related: list[dict] | None) -> Triage:
        evidence = build_evidence(incident, store, self.router, now, related=related)
        log: list[tuple[str, str]] = []

        def sql(q: str) -> str:
            out = run_sql(store, q)
            log.append((q, out))
            return out

        prompt = ("Evidence pack (JSON):\n```json\n" + json.dumps(evidence, ensure_ascii=False, default=str)
                  + "\n```\nInvestigate with sql where it helps, then return the triage.")
        kw = dict(system=self.system, schema=TRIAGE_SCHEMA, model=self.model, effort=self.effort,
                  max_turns=self.max_turns, budget_usd=self.budget, sql=sql)
        result = self.runner(prompt=prompt, **kw)
        self.cost_usd += result.cost_usd or 0.0
        triage = triage_from_output(result.output, incident.role)
        unverified = verify_numbers(_texts(triage), known_numbers(evidence, [o for _, o in log]))
        unverified_first, fixed = bool(unverified and result.session_id), None
        if unverified_first:
            fixed = self.runner(prompt=REPAIR.format(numbers=", ".join(unverified)), resume=result.session_id, **kw)
            self.cost_usd += fixed.cost_usd or 0.0
            triage = triage_from_output(fixed.output, incident.role)
            unverified = verify_numbers(_texts(triage), known_numbers(evidence, [o for _, o in log]))
        triage.unverified = unverified
        triage.queries = [q.strip() for q, out in log if not out.startswith("ERROR")][:6]
        triage.source, triage.model = "claude", self.model
        triage.votes = {"rules": incident.role, "analyst": triage.assignee}
        triage.cost_usd = round((result.cost_usd or 0.0) + ((fixed.cost_usd or 0.0) if fixed else 0.0), 4)
        return triage


def ollama_url(host: str | None) -> str:
    host = host or "http://127.0.0.1:11434"
    return host if host.startswith("http") else f"http://{host}"


def ollama_json(host: str, model: str, system: str, user: str, schema: dict, think: bool = False,
                timeout: float = 300.0) -> dict:
    """One structured Ollama chat call (format = JSON schema)."""
    r = httpx.post(f"{ollama_url(host)}/api/chat", timeout=timeout, json={
        "model": model, "stream": False, "think": think, "format": schema, "options": {"temperature": 0},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
    r.raise_for_status()
    return json.loads(r.json()["message"]["content"])


class OllamaAnalyst:
    """Local-only mode: one structured call over the evidence pack (no tool use), same verification."""

    name = "ollama"

    def __init__(self, router: Router, model: str = "qwen3:14b", host: str | None = None):
        self.router, self.model, self.host = router, model, ollama_url(host or os.environ.get("OLLAMA_HOST"))
        self.system = (PROMPTS / "analyst.md").read_text().replace(
            "You can query the same data with the `sql` tool (read-only DuckDB, at most 50 rows per query).",
            "Work from the evidence pack only.")

    def triage(self, incident: Incident, store: Store, now: datetime, related: list[dict] | None = None) -> Triage:
        try:
            evidence = build_evidence(incident, store, self.router, now, related=related)
            out = ollama_json(self.host, self.model, self.system,
                              "Evidence pack (JSON):\n" + json.dumps(evidence, ensure_ascii=False, default=str),
                              TRIAGE_SCHEMA)
            triage = triage_from_output(out, incident.role)
            triage.unverified = verify_numbers(_texts(triage), known_numbers(evidence, []))
            triage.source, triage.model = "ollama", self.model
            triage.votes = {"rules": incident.role, "analyst": triage.assignee}
            return triage
        except Exception as e:  # noqa: BLE001
            rules = fallback_triage(incident, self.router)
            rules.arbiter_note = f"Локальная модель недоступна ({str(e)[:160]}); текст задачи собран правилами."
            return rules
