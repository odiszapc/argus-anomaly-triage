"""LLM wiring. Modes: claude (Claude analyst + local arbiter), local (everything on Ollama), off (rules only),
auto (claude when credentials or the Claude Code CLI are present, else local when Ollama answers, else off)."""

from __future__ import annotations

import os
import shutil

import httpx

from ..config import Config
from ..routing import Router
from .analyst import ClaudeAnalyst, OllamaAnalyst, ollama_url
from .arbiter import ClaudeArbiter, OllamaArbiter


def ollama_has(host: str, model: str) -> bool:
    try:
        tags = httpx.get(f"{ollama_url(host)}/api/tags", timeout=2.0).json().get("models", [])
        return any(m.get("name") == model or m.get("model") == model for m in tags)
    except (httpx.HTTPError, ValueError):
        return False


def claude_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN") or shutil.which("claude"))


def make_analyst_and_arbiter(cfg: Config, router: Router, mode: str):
    from ..engine import RulesAnalyst

    llm = cfg.llm or {}
    host = os.environ.get("OLLAMA_HOST") or llm.get("ollama_host")
    local_model = llm.get("arbiter_model", "qwen3:14b")
    local_ok = ollama_has(host, local_model)
    if mode == "auto":
        mode = "claude" if claude_available() else ("local" if local_ok else "off")
    if mode == "off":
        return RulesAnalyst(router), None
    if mode == "local":
        return OllamaAnalyst(router, llm.get("local_analyst_model", local_model), host), \
            (OllamaArbiter(local_model, host) if local_ok else None)
    analyst = ClaudeAnalyst(router, model=llm.get("analyst_model", "claude-opus-5-5"),
                            effort=llm.get("effort", "medium"), max_turns=int(llm.get("max_turns", 10)),
                            budget_usd=float(llm.get("max_budget_usd", 2.0)))
    arbiter = OllamaArbiter(local_model, host) if local_ok else ClaudeArbiter(llm.get("claude_arbiter_model",
                                                                                      "claude-sonnet-5-5"))
    return analyst, arbiter
