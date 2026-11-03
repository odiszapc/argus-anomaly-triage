import asyncio
from datetime import timedelta

from conftest import T0, log_line

from argus.config import load_config
from argus.ingest import ingest
from argus.mcp_server import build_server


def test_mcp_server_exposes_read_only_tools(dataset, tmp_path):
    data = dataset(logs=[log_line(T0 + timedelta(minutes=i), "Redis failure") for i in range(5)], points=6)
    ingest(data, tmp_path / "var")
    cfg = load_config(None, data_dir=data, var_dir=tmp_path / "var", out_dir=tmp_path / "out")
    server = build_server(cfg)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {"sql", "schema", "list_tasks", "get_task"} <= names
    ok = str(asyncio.run(server.call_tool("sql", {"query": "SELECT count(*) AS n FROM logs"})))
    assert "n" in ok and "5" in ok
    denied = str(asyncio.run(server.call_tool("sql", {"query": "DROP TABLE raw.logs"})))
    assert "ERROR" in denied
