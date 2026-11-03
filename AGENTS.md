# AGENTS.md — working on Argus with a coding agent

Argus watches app metrics and error logs, finds anomalies without looking ahead, and files a triage task
(`tasks/`), Slack payloads (`slack-log.json`) and a post-mortem draft (`postmortems/`) per incident.
Statistics find and group anomalies; an LLM agent writes the triage; code checks the numbers; a second
model votes on the owner. Read this file before changing anything.

## Map

| Path | What it does |
|---|---|
| `src/argus/ingest.py`, `templates.py` | raw export → `var/argus.duckdb` (logs templated by SQL masks, time-sorted) |
| `src/argus/store.py` | read-only views filtered by a moving `now` — the no-look-ahead guarantee |
| `src/argus/detect/` | causal detectors: log bursts, RPS artifacts, CPU, traffic, country shifts, bot features |
| `src/argus/correlate.py` | `IncidentBook`: signals → incidents, lifecycle, severity, reopen of regressions |
| `config/routing.yaml` | component → owner role, cause/symptom, starting hypotheses (edit this, not code) |
| `src/argus/engine.py` | ticks, tasks, Slack, predictions, persisted state (`<out>/.argus/state.pkl`) |
| `src/argus/llm/` | analyst (Claude Agent SDK + read-only SQL tool), number verifier, arbiter (Ollama), vote |
| `src/argus/dedup.py`, `predict.py` | repeat detection before task creation; recurrence predictions |
| `src/argus/render/` | Jinja templates for tasks and post-mortems, Slack Block Kit |
| `evals/gold.yaml`, `src/argus/evals.py` | labelled incidents and the scorer behind `make eval` |
| `config/argus.yaml` | every threshold the code uses, with defaults |

## Commands

```
make setup ingest            # deps, then ~30 s to load the 16 GB export
make replay-offline eval     # rules only, ~30 s, then the score card
make replay eval             # with the LLM analyst (needs ANTHROPIC_API_KEY or a Claude Code login) and Ollama
make test lint
uv run argus sql "SELECT ..."   # the analyst's read-only SQL from the shell
```

## Invariants (tests pin each one; do not weaken them)

1. **No look-ahead.** Detectors use only past buckets; everything at tick `now` reads the guarded views.
   Replaying the full history must equal running live (`tests/test_engine.py::test_replay_has_no_lookahead`).
2. **Bucket labels are window ends**: label `T` covers `[T-10m, T)`, like the metric exports.
3. **`undefined` in the CSV exports is missing data, never zero** (top-k exports drop countries/endpoints).
4. **Every number an LLM writes is verified** against the evidence pack and its own SQL results
   (`llm/verify.py`); unverified numbers are listed in the task, never silently kept.
5. **An LLM failure never loses an alert**: the rules-only triage is the fallback.
6. **Reruns are idempotent**: the cursor in `<out>/.argus/state.pkl` prevents duplicate tasks and posts.
7. **The SQL tool is read-only**: one SELECT, whitelisted views (checked on DuckDB's parse tree), no file access.

## How to change things

- **Routing or hypotheses** — edit `config/routing.yaml`; add a test in `tests/test_correlate.py` with a
  synthetic signal; `make replay-offline eval`.
- **A threshold** — change `config/argus.yaml`, run `make replay-offline eval`, compare recall, assignee
  accuracy, TTD and the "без эталонной метки" list before/after. Put the numbers in the commit message.
- **A detector** — write the failing test first on a synthetic series (see `tests/test_detectors.py`),
  keep it causal (only `shift(k>0)` / trailing windows), return `Signal`s with `points`.
- **Prompts** — `src/argus/llm/prompts/*.md`. Do not add numbers to prompts; the verifier will flag them.
- **A new data source** — see `.claude/skills/add-data-source`.

Never edit `evals/gold.yaml` to make a score go up. Labels change only when the data says the label was
wrong; write down why in the commit.

## Skills and tools for agents

- `.mcp.json` registers `argus mcp`: tools `sql`, `schema`, `list_tasks`, `get_task`.
- `.claude/skills/investigate-incident` — dig into a task and fill the post-mortem draft.
- `.claude/skills/tune-detection` — change detection safely with the eval loop.
- `.claude/skills/add-data-source` — plug in Prometheus, Loki or ClickHouse instead of file exports.

## Style

Python 3.12, ruff (line 120). Small modules with one job. Russian for anything a person on call reads
(tasks, Slack, post-mortems); English for code, comments and this file.
