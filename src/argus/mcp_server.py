"""MCP server for people (and their agents) investigating Argus incidents: `argus mcp`, stdio.

The same read-only SQL tool the analyst agent uses, over the full history, plus the task tracker.
Claude Code picks it up from .mcp.json in the repository root.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .config import Config
from .llm.tools import SCHEMA_DOC, run_sql
from .store import Store
from .tracker import Tracker

INSTRUCTIONS = ("Argus data: error logs and app metrics (UTC). Start with list_tasks, read a task with get_task, "
                "then check hypotheses with sql. Prefer the 10-minute aggregates over raw logs.")


def build_server(cfg: Config) -> MCPServer:
    server = MCPServer("argus", instructions=INSTRUCTIONS)
    store = Store(cfg.paths.db)
    tracker = Tracker(cfg.paths.out_dir)

    @server.tool(description="Read-only DuckDB SQL over logs and metrics (max 200 rows).\n" + SCHEMA_DOC)
    def sql(query: str) -> str:
        return run_sql(store, query, max_rows=200, timeout_s=60)

    @server.tool(description="Tables, columns and conventions of the Argus data.")
    def schema() -> str:
        return SCHEMA_DOC

    @server.tool(description="Tasks Argus created: id, severity, assignee, status, title, start time.")
    def list_tasks() -> str:
        rows = [f"{t['id']} {t.get('severity')} {t.get('assignee')} {t.get('status')} {t.get('started_at')} "
                f"{t.get('title')}" for t in tracker.list()]
        return "\n".join(rows) or "no tasks yet: run `argus replay` or `argus run`"

    @server.tool(description="Full markdown of one task (with its signals, votes and history), by id like ARG-007.")
    def get_task(task_id: str) -> str:
        for t in tracker.list():
            if t["id"] == task_id.strip().upper():
                from pathlib import Path
                return Path(t["path"]).read_text()
        return f"ERROR: no task {task_id}"

    return server
