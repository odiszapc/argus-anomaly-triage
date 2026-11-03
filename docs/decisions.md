# Решения по ходу реализации

Выборы, которые план оставлял открытыми, и отступления от него: что решено, почему и чего стоит ошибка. Журнал вёлся по ходу работы (план: `docs/superpowers/plans/2026-11-03-argus.md`).

- **Setup**: new repo, so no worktree; initial commit on main, all work on branch feat/argus — keeps main clean without asking — cost if wrong: one merge.
- **Task 3**: detectors run once over full data in replay (all baselines causal) and the engine reveals signals by detected_at/truncates at now; watch mode recomputes at each tick — same code; a no-look-ahead test pins equivalence — cost if wrong: replay TTD optimistic.
- **Task 3**: `new_signature` is an attribute of log_burst (a new template bursting has baseline 0 → flagged anyway), not a separate kind — cost if wrong: none.
- **Task 3**: bot_activity is a feature function (ISP share jump + IP rotation) applied to an incident's window in correlation, not a standalone detector (we only have error logs, the burst detector already triggers) — cost if wrong: a silent bot without errors is missed (not observable in this data anyway).
- **Task 3**: endpoint latency is evidence enrichment, not a detector (30-min step, mostly symptom) — cost if wrong: latency-only incidents missed.
- **Task 3**: rps artifact = |rps_ratio-1|>=0.5 while cpu and country-sum ratios stay within ±15%; baseline recomputed on the artifact-cleaned series (12 fake "drops" came from artifacts inflating the same-time median). Country shift: ratio>=1.5 or <=0.65, |r_c-r_global|>=0.3, min 6 buckets, gap 3, 2 days history, no fallback. Global traffic: |r-1|>=0.25, 3 buckets, 2 days history. Warm-up 6 h for log templates (hourly 'wait exceeded' bursts on day 1 are seasonal).
- **Task 4**: correlation is stateful (IncidentBook.step(signals, now) attaches each new signal to a co-active open incident or starts one) instead of a stateless correlate(signals, now) — a 10-day regression (lock-wait) would otherwise swallow every overlapping incident, and identities must survive ticks — cost if wrong: none for outputs, Task 6 engine wraps the book.
- **Task 4**: incidents open only after one more bucket (lets the cause signal arrive: REST timeouts at 11:30, Valkey LOADING at 11:40) and when sustained (>=2 buckets & >=1000 clients) or big (>=5000 clients) or recurring (3rd blip with the same fingerprint in 24 h); short low-impact spikes resolve as blips with no task — cost if wrong: +10 min TTD.
- **Task 4**: upstream-only incidents (REST/GRPC timeouts, no DB/cache/DNS/app cause) that coincide with a load signal (rps_shift up, cpu_high) route to PaaS (capacity), otherwise Backend Lead; bot features override to Security Lead — cost if wrong: one role per edge case, the LLM vote can still flip it.
- **Task 4**: impact/levels/bot features come through a Probe interface (StoreProbe = SQL, tests use a fake) — cost if wrong: none.
- **Task 4**: only components of a merge family (data_store) share an incident; symptoms join the highest-priority co-active incident; a cause reassigns an open symptom-only incident within 30 min only if new or lasting; weak causes (familiar, <5% of volume, one bucket) never lead. Severity = peak 10-min error rate (>=1% SEV-1, >=0.1% SEV-2) or clients (>=500k / >=50k) or CPU>=85%; abuse >= SEV-2; SEV-1 cools down 2 h. Long regressions (cause anchor, >=6 h) stay open on the 1-h median vs the 24-h pre-incident level and reopen within 72 h — I3 is one incident 08-25 15:10 → 09-04 13:00 — cost if wrong: late resolve times on SEV-1.
- **Task 7**: Claude analyst runs through the Claude Agent SDK (in-process MCP sql tool, json_schema output, setting_sources=[] / skills=[] / tools=[] isolation) instead of the raw Messages API — the only credential on this machine is a Claude Code login and the SDK accepts ANTHROPIC_API_KEY too; model claude-opus-5-5 (skill default), effort medium, ≤10 turns, ≤$2 per incident — cost if wrong: reviewers need the bundled CLI (pip installs it).
- **Task 7**: SQL whitelist is checked on DuckDB's parse tree (json_serialize_sql), because get_table_names resolves the guarded views to raw.* — cost if wrong: none.
- **Task 7**: local mode analyst is a single structured Ollama call over the evidence pack (no tool use); arbiter gets "blind" evidence (no rules opinion, no analyst text) and votes with rules+analyst — cost if wrong: weaker local-only triage.
- **Task 8**: dedup matches against the engine's task records (mirror of the tracker front matter) — same problem family + Jaccard(cause templates)>=0.34 or embedding cosine>=0.85, within 72 h of last activity; a never-seen cause template means a new failure mode → new task. Dedup runs before the LLM so repeats cost nothing — cost if wrong: a repeat with a new symptom mix becomes its own task.
- **Task 8**: prediction = recurrence watch (after a SEV-1/2 data-store/infra incident resolves, forecast the next RPS ramp to the level the incident began at, from same-time medians of previous days) instead of a generic trend forecaster; precursor trend deferred — cost if wrong: no early warning for first-time incidents.
- **Task 8**: dedup also matches when the new incident's dominant cause template already belongs to the task (Jaccard alone missed MongoDB 08-26 vs 08-25); task severity = worst of its incidents and a repeat that escalates past it gets a fresh LLM triage + broadcast; predictions only for incidents that began above the 24-h median RPS, once per task per day; a new cause (new template) reclaims symptoms that arrived a bucket before it from lower-priority incidents — real data: 14 tasks + 22 repeats, 3 of 5 predictions hit — cost if wrong: see eval.

## Финальное ревью

Независимое ревью всей ветки (Claude Fable 5.1): 1 критичная, 6 важных и 8 мелких находок. Критичная и важные исправлены; на каждую сначала написан падающий тест.

- fixed state saved only at pass end (killed CronJob duplicated tasks/posts) — test_interrupted_pass_does_not_duplicate_on_retry RED→GREEN, suite 111/111; plus atomic write (tmp+os.replace), loud load error, `run --max-seconds 600`.
- fixed verifier skipped dot-decimals with units and percentages <=10, and counted ids/timestamps from SQL output as evidence — test_verifier_checks_dot_decimals_and_small_percentages, test_tool_output_ids_and_timestamps_do_not_verify_numbers RED→GREEN.
- fixed cpu_high forced SEV-1 regardless of impact (now raises to SEV-2) — test_cpu_saturation_alone_does_not_make_sev1 RED→GREEN.
- fixed NaN points in truncated metric episodes made totals NaN — test_truncate_ignores_missing_points RED→GREEN.
- fixed schema-valid but empty LLM answer produced an empty task — test_empty_llm_answer_falls_back_to_rules RED→GREEN.
- Ruling: "old pickles crash on new fields" — not reproducible: dataclass fields with plain defaults resolve via class attributes; added _fill_defaults for default_factory fields anyway; regression test passes — cost if wrong: one AttributeError after an upgrade.
- Ruling: live-vs-replay equivalence was asked for as a test; it already held (test_live_ticks_equal_replay passes) — cost if wrong: none.

Отложено (мелкие):

- task ids from files on disk, not a counter in state (delete a file → id reuse).
- prediction de-dup per day is process-local across cron passes.
- owner/_elevated maps never pruned in long-running watch.
- during outages a single RPS artifact can count as corroborated rps_shift and push an upstream incident to PaaS.
- log-pipeline gaps read as zero errors for anchors (regression resolves, then reopens as the same task).
- pickle state on a shared volume = code execution for whoever can write it; JSON state would close it.
- watch re-detects the full history every pass (fine for 14 days, unbounded later).
- SQL timeout timer shares the engine's connection (interrupt could land on an idle connection; untested).
