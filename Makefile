DATA ?= ../data
OUT ?= .

.PHONY: setup ingest replay replay-offline run eval report test lint mcp docker

setup:            ## install dependencies (uv)
	uv sync
ingest:           ## load the raw export (16 GB JSON + CSV) into var/argus.duckdb, ~30 s
	uv run argus ingest --data $(DATA)
replay:           ## full 14-day replay with the LLM analyst and arbiter, outputs into $(OUT)
	uv run argus replay --fresh --out $(OUT)
replay-offline:   ## same replay with rules only (no models), into out-offline/
	uv run argus replay --fresh --llm off --out out-offline
run:              ## one pass from the saved cursor (cron mode)
	uv run argus run --out $(OUT)
eval:             ## score the last run against evals/gold.yaml
	uv run argus eval --out $(OUT)
report:           ## report.html for the last run
	uv run argus report --out $(OUT)
test:
	uv run pytest
lint:
	uv run ruff check src tests
mcp:              ## MCP server for Claude Code (also registered in .mcp.json)
	uv run argus mcp
docker:
	docker build -t argus:dev .
