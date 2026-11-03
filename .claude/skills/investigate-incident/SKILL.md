---
name: investigate-incident
description: Use when asked to investigate an Argus task (ARG-xxx), an alert from #app-alerts, or an anomaly window, and to fill in the post-mortem draft with confirmed facts.
---

# Investigate an Argus incident

1. `list_tasks` (MCP `argus`) or `ls tasks/`; open the task with `get_task ARG-xxx`. Read Symptoms,
   Hypotheses, votes and the Data table first: they say what code already measured.
2. Find what started first. Per-minute counts of the task's templates around the start:
   ```sql
   SELECT date_trunc('minute', ts) m, tpl, count(*) n FROM logs
   WHERE ts BETWEEN TIMESTAMP '…' - INTERVAL 30 MINUTE AND TIMESTAMP '…' + INTERVAL 30 MINUTE
     AND tpl_id IN ('…') GROUP BY ALL ORDER BY m, n DESC
   ```
3. Check concentration — one host (bad pod/node), one country (network, SEO), one ISP with fresh IPs per
   request (bots):
   ```sql
   SELECT host, count(*) FROM logs WHERE ts BETWEEN … AND tpl_id = '…' GROUP BY 1 ORDER BY 2 DESC LIMIT 10
   SELECT isp, count(*) n, count(DISTINCT ip) ips FROM logs WHERE ts BETWEEN … GROUP BY 1 ORDER BY n DESC LIMIT 10
   ```
4. Compare with the same window yesterday (`metric_rps`, `metric_cpu`, `metric_endpoint`, `agg_tpl_10m`).
5. Write findings into `postmortems/ARG-xxx-….md` only in the sections marked **[SRE]**; keep the
   generated facts. Every number you add must come from a query you ran; quote the query.
6. If the owner is wrong, change `config/routing.yaml` (see `tune-detection`), not the task file.
