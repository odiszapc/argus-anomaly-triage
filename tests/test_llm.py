import json
from datetime import timedelta

import pytest
from conftest import T0, log_line

from argus.ingest import ingest
from argus.llm.analyst import ClaudeAnalyst, triage_from_output
from argus.llm.tools import run_sql
from argus.llm.verify import extract_numbers, verify_numbers
from argus.llm.vote import Verdict, vote
from argus.routing import Router
from argus.store import Store


@pytest.fixture
def store(dataset, tmp_path):
    logs = [log_line(T0 + timedelta(minutes=i), "Redis failure", user_id=str(i)) for i in range(120)]
    ingest(dataset(logs=logs, points=24), tmp_path / "var")
    return Store(tmp_path / "var" / "argus.duckdb", now=T0 + timedelta(minutes=60))


def test_sql_tool_rejects_writes_and_raw_tables(store):
    for bad in ("DELETE FROM logs", "CREATE TABLE x AS SELECT 1", "SELECT * FROM raw.logs", "SELECT 1; SELECT 2",
                "SELECT * FROM read_csv('/etc/passwd')"):
        assert run_sql(store, bad).startswith("ERROR"), bad


def test_sql_tool_respects_now(store):
    out = run_sql(store, "SELECT count(*) AS n FROM logs")
    assert out.splitlines()[1] == "60"  # 120 lines exist, 60 happened before now


def test_sql_tool_caps_rows(store):
    out = run_sql(store, "SELECT ts FROM logs ORDER BY ts", max_rows=10)
    assert len(out.splitlines()) == 1 + 10 + 1 and "обрезано" in out.splitlines()[-1]


def test_number_extraction_reads_russian_formats():
    found = {raw: v for raw, v in extract_numbers("≈8,56 млн клиентов, 17,5 тыс. строк, пик 4,0 %, 1 234 запроса")}
    assert found["8,56 млн"] == pytest.approx(8.56e6) and found["17,5 тыс."] == pytest.approx(17500)
    assert found["4,0 %"] == pytest.approx(4.0) and found["1 234"] == pytest.approx(1234)


def test_verifier_flags_invented_number():
    known = [8_561_654, 0.0401, 17_472, 2026, 11]
    assert verify_numbers(["≈8,56 млн клиентов, пик ошибок 4,0 %, в 11:40 UTC 02.09"], known) == []
    assert verify_numbers(["затронуто 99 999 клиентов"], known) == ["99 999"]
    assert verify_numbers(["шаблон «timed out after 1000 milliseconds»"], known) == []  # quoted log text is not a claim


def test_vote_majority_and_split():
    yes = Verdict(True, "DBA", "SEV-1", 0.8, "кэш")
    assert vote("DBA", "Backend Lead", yes)[:2] == ("DBA", False)
    split = vote("DBA", "Backend Lead", Verdict(True, "PaaS Engineer", "SEV-2", 0.6, "трафик"))
    assert split[1] is True
    doubt = vote("DBA", "DBA", Verdict(False, "DBA", "SEV-3", 0.7, "похоже на шум"))
    assert doubt[0] == "DBA" and doubt[1] is True


def test_triage_from_output_rejects_unknown_role():
    out = {"title": "t", "summary": "s", "symptoms": ["a"], "assignee": "CTO", "assignee_reason": "r",
           "hypotheses": [{"cause": "c", "evidence": "e", "confidence": "высокая"}], "next_steps": ["n"]}
    t = triage_from_output(out, rules_role="DBA")
    assert t.assignee == "DBA" and t.title == "t"


def test_analyst_failure_falls_back(store):
    from test_render import incident

    def broken(*args, **kwargs):
        raise RuntimeError("model unavailable")

    t = ClaudeAnalyst(Router.load(), runner=broken).triage(incident(), store, T0 + timedelta(minutes=60))
    assert t.source == "rules" and t.assignee == "DBA" and "model unavailable" in t.arbiter_note


def test_evidence_pack_is_small_and_has_no_future(store):
    from test_render import incident

    from argus.evidence import build_evidence

    inc = incident()
    now = T0 + timedelta(minutes=60)
    pack = build_evidence(inc, store, Router.load(), now)
    text = json.dumps(pack, ensure_ascii=False, default=str)
    assert len(text.encode()) <= 10_000
    assert pack["incident"]["now"] == now.strftime("%Y-%m-%d %H:%M")


def test_outvoted_arbiter_is_reported_as_dissent(store):
    from test_render import incident

    from argus.llm.arbiter import BaseArbiter
    from argus.triage import fallback_triage

    class Dissent(BaseArbiter):
        model = "qwen3:14b"

        def judge(self, evidence):
            return Verdict(True, "Backend Lead", "SEV-2", 0.6, "рост ошибок приложения")

    inc = incident()
    t = fallback_triage(inc, Router.load())
    t.source, t.votes = "claude", {"rules": "DBA", "analyst": "DBA"}
    Dissent().review(inc, t, store, T0 + timedelta(minutes=60), Router.load())
    assert t.assignee == "DBA" and not t.needs_human
    assert "предлагал Backend Lead" in t.arbiter_note


def test_analyst_uses_agent_output_and_counts_cost(store):
    from test_render import incident

    from argus.llm.analyst import AgentResult

    out = {"title": "Valkey недоступен", "summary": "Кэш перезапустился.", "symptoms": ["LOADING"],
           "hypotheses": [{"cause": "рестарт", "evidence": "LOADING", "confidence": "высокая"}], "assignee": "DBA",
           "assignee_reason": "кэш", "next_steps": ["проверить узлы"], "impact_note": "оценка"}
    calls = []

    def runner(**kw):
        calls.append(kw)
        return AgentResult(out, "s1", 0.25)

    t = ClaudeAnalyst(Router.load(), runner=runner).triage(incident(), store, T0 + timedelta(minutes=60))
    assert (t.source, t.title, t.cost_usd, len(calls)) == ("claude", "Valkey недоступен", 0.25, 1)


def test_vote_keeps_rules_backed_by_a_new_signature():
    llm = Verdict(True, "Backend Lead", "SEV-1", 0.7, "таймауты REST")
    role, needs_human, note = vote("DBA", "Backend Lead", llm, rules_strong=True)
    assert role == "DBA" and needs_human and "DBA" in note


def test_verifier_checks_dot_decimals_and_small_percentages():
    known = [8_561_654, 0.007]
    assert verify_numbers(["≈8.99 млн клиентов"], known) == ["8.99 млн"]
    assert verify_numbers(["7 % запросов падали"], known) == ["7 %"]
    assert verify_numbers(["0,7 % запросов падали"], known) == []


def test_tool_output_ids_and_timestamps_do_not_verify_numbers():
    from argus.llm.verify import known_numbers
    known = known_numbers({}, ["ts,ip,n\n2026-09-02 11:40:00,10.0.0.100,42"])
    assert 42 in known and 100 not in known and 11 not in known


def test_empty_llm_answer_falls_back_to_rules(store):
    from test_render import incident

    from argus.llm.analyst import AgentResult
    empty = {"title": "", "summary": "", "symptoms": [], "hypotheses": [], "assignee": "DBA",
             "assignee_reason": "", "next_steps": [], "impact_note": ""}
    t = ClaudeAnalyst(Router.load(), runner=lambda **kw: AgentResult(empty, None, 0.1)).triage(
        incident(), store, T0 + timedelta(minutes=60))
    assert t.source == "rules" and t.title and t.symptoms
