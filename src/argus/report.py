"""One self-contained HTML page about a run: score card, 14-day timeline with incidents, tasks, eval, predictions.

`argus report` writes <out>/report.html. CSS, JS and data are inline, so the file opens from disk with no network.
Reads the persisted run state (<out>/.argus/state.pkl), the labelled incidents and, for the background chart,
the DuckDB views up to the run's cursor.
"""

from __future__ import annotations

import html
import json
import pickle
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .config import Config
from .evals import EvalResult, detections_from, evaluate, load_gold
from .render.fmt import dur, human
from .render.task import VOTERS, stem, ttd_minutes
from .store import Store
from .timeutil import BUCKET

EPOCH = datetime(1970, 1, 1)
SEV_NAMES = {"SEV-1": "критический", "SEV-2": "серьёзный", "SEV-3": "умеренный", "SEV-4": "низкий"}
SOURCES = {"rules": "правила", "claude": "Claude", "ollama": "Ollama"}
SERIES = {  # key: (label, scale, query over the guarded views)
    "errors": ("Строки ошибок в логах за 10 мин", "log", "SELECT bucket AS ts, n AS value FROM agg_logs_10m"),
    "rps": ("RPS, запросов в секунду", "linear", "SELECT ts, value FROM metric_rps"),
    "cpu": ("CPU, % (среднее по кластеру)", "linear", "SELECT ts, value FROM metric_cpu"),
}
TOGGLE = {"errors": "Ошибки в логах (лог. шкала)", "rps": "RPS", "cpu": "CPU"}


def load_memory(cfg: Config):
    state = cfg.paths.out_dir / ".argus" / "state.pkl"
    if not state.exists():
        raise FileNotFoundError(f"no run state at {state}; run `argus replay` first")
    return pickle.loads(state.read_bytes())


def build_report(cfg: Config) -> str:
    memory = load_memory(cfg)
    gold = load_gold(cfg.paths.gold) if cfg.paths.gold.exists() else []
    result = evaluate(gold, detections_from(memory), memory.predictions)
    by_uid = {i.uid: i for i in memory.incidents}
    records = sorted(memory.tasks.values(), key=lambda r: r.task_id)
    metrics = _metrics(cfg.paths.db, memory.cursor)
    period = metrics["period"] if metrics else _fallback_period(memory, by_uid, records)
    data = {
        "range": [_ms(period[0]), _ms(period[1])],
        "t0": _ms(metrics["t0"]) if metrics else None,
        "step": int(BUCKET.total_seconds() * 1000),
        "series": [{"key": k, "label": SERIES[k][0], "scale": SERIES[k][1], "values": v}
                   for k, v in (metrics["series"].items() if metrics else [])],
        "tasks": [_task_json(rec, by_uid) for rec in records],
        "sevNames": SEV_NAMES,
    }
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    body = "".join([
        _header(cfg, memory, records, period),
        _kpis(records, result),
        _timeline(metrics, records, by_uid),
        _tasks_table(records, by_uid, cfg.paths.out_dir),
        _eval_section(result, cfg),
        _predictions(memory.predictions, result),
        f'<footer>argus report · состояние: {_e(cfg.paths.out_dir / ".argus" / "state.pkl")} · '
        f"данные: {_e(cfg.paths.db)}</footer>",
    ])
    return (f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Argus: отчёт о прогоне</title><style>{CSS}</style></head><body><main>{body}</main>"
            f'<script type="application/json" id="argus-data">{blob}</script><script>{JS}</script></body></html>')


# ---------- data ----------

def _metrics(db: Path, until: datetime | None) -> dict | None:
    """Background series on one 10-minute grid, cut at the run's cursor (what the run could see)."""
    if not db.exists():
        return None
    store = Store(db, now=until)
    try:
        period = store.time_range()
        frames = {k: store.df(f"{q} ORDER BY ts") for k, (_, _, q) in SERIES.items()}
    finally:
        store.close()
    stamps = [ts.to_pydatetime() for f in frames.values() for ts in f["ts"]]
    if not stamps or period[0] is None:
        return None
    t0, t1 = min(stamps), max(stamps)
    n = int((t1 - t0) / BUCKET) + 1
    series: dict[str, list] = {}
    for key, frame in frames.items():
        values: list = [None] * n
        for ts, v in zip(frame["ts"], frame["value"], strict=True):
            if v is None or v != v:  # NULL / NaN is missing data, never zero
                continue
            i = round((ts.to_pydatetime() - t0) / BUCKET)
            if 0 <= i < n:
                values[i] = round(float(v), 1) if key == "cpu" else int(round(float(v)))
        series[key] = values
    return {"period": period, "t0": t0, "series": series}


def _fallback_period(memory, by_uid, records) -> tuple[datetime, datetime]:
    starts = [by_uid[r.incident_uid].start - BUCKET for r in records]
    end = memory.cursor or max((_end(by_uid[r.incident_uid]) for r in records), default=datetime.now(UTC))
    return (min(starts, default=end), end)


def _end(inc) -> datetime:
    return max(inc.end, inc.start) if inc.signals else inc.last_active


def _segments(inc) -> list[list[int]]:
    """Windows where the incident's signals were actually anomalous, merged when they touch.

    An incident can stay alive for days on intermittent bursts; one solid bar would read as a continuous outage.
    """
    spans = sorted((s.start - BUCKET, s.end) for s in inc.signals.values()) or [(inc.start - BUCKET, _end(inc))]
    merged: list[list[datetime]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [[_ms(a), _ms(b)] for a, b in merged]


def _task_json(rec, by_uid) -> dict:
    root = by_uid[rec.incident_uid]
    incs = [(root, False)] + [(by_uid[r["uid"]], True) for r in rec.repeats if r["uid"] in by_uid]
    return {"id": rec.task_id, "sev": rec.severity, "title": rec.triage.title, "who": rec.triage.assignee,
            "spans": [{"s": _ms(i.start - BUCKET), "e": _ms(_end(i)), "segs": _segments(i),
                       "d": _ms(i.detected_at) if i.detected_at else None,
                       "ttd": dur(ttd_minutes(i)) if i.detected_at else "—", "sev": i.severity, "rep": rep,
                       "clients": human(i.impact.clients) if i.impact.clients else ""} for i, rep in incs]}


# ---------- sections ----------

def _header(cfg, memory, records, period) -> str:
    lo, hi = period
    llm = [r for r in records if r.triage.source != "rules"]
    models = sorted({f"{SOURCES.get(r.triage.source, r.triage.source)} {r.triage.model}".strip() for r in llm})
    mode = (f"LLM-аналитик в {len(llm)} из {len(records)} задач ({', '.join(models)})" if llm
            else "только правила, LLM не вызывался")
    now = datetime.now(UTC)
    return (f"<header><h1>Argus: что нашла система</h1>"
            f'<p class="meta">Период данных: <b>{lo:%Y-%m-%d %H:%M} → {hi:%Y-%m-%d %H:%M} UTC</b> '
            f"({_plural(round((hi - lo).total_seconds() / 86400), ('день', 'дня', 'дней'))})"
            f" · обработано до {_ts(memory.cursor, '%Y-%m-%d %H:%M')} · анализ: {_e(mode)}"
            f" · отчёт сформирован {now:%Y-%m-%d %H:%M} UTC</p>"
            f'<p class="meta">Прогон: {_e(cfg.paths.out_dir)}</p></header>')


def _kpis(records, result: EvalResult) -> str:
    repeats = sum(len(r.repeats) for r in records)
    found = sum(1 for r in result.rows if r.task)
    llm = sum(1 for r in records if r.triage.source != "rules")
    cost = sum(r.triage.cost_usd for r in records)
    hits, preds = result.prediction_hits, len(result.predictions)
    cards = [
        ("Задачи", str(len(records)), f"+ {_plural(repeats, ('повтор', 'повтора', 'повторов'))} внутри задач"),
        ("Эталонные инциденты найдены", f"{found} из {len(result.rows)}", f"recall {_pct0(result.recall)}"),
        ("Исполнитель назначен верно", _pct0(result.role_accuracy) if found else "—", "среди найденных эталонных"),
        ("Медианное время до оповещения",
         dur(result.median_ttd_min) if result.median_ttd_min is not None else "—", "от начала аномалии до задачи"),
        ("Прогнозы повтора сбылись", f"{hits} из {preds}", "окно риска, выставленное заранее"),
        ("LLM-анализы", str(llm), f"стоимость ${cost:.2f}" if llm else "прогон без LLM: правила"),
        ("Без эталонной метки", str(len(result.unlabelled)), "ложные срабатывания или неразмеченные"),
    ]
    return '<section class="kpis">' + "".join(
        f'<div class="kpi"><div class="label">{_e(a)}</div><div class="value">{_e(b)}</div>'
        f'<div class="sub">{_e(c)}</div></div>' for a, b, c in cards) + "</section>"


def _timeline(metrics, records, by_uid) -> str:
    toggle = ""
    if metrics:
        toggle = '<fieldset class="seg"><legend>Фон графика</legend>' + "".join(
            f'<label><input type="radio" name="tl-series" value="{k}"{" checked" if i == 0 else ""}>'
            f"<span>{_e(TOGGLE[k])}</span></label>" for i, k in enumerate(SERIES)) + "</fieldset>"
    legend = "".join(f'<span><i class="sw k{s[-1]}"></i>{s} {n}</span>' for s, n in SEV_NAMES.items())
    legend += ('<span><i class="sw neutral"></i>инцидент, по которому открыта задача</span>'
               '<span><i class="sw neutral thin"></i>повтор, свёрнутый в ту же задачу</span>')
    return (f'<section class="card"><div class="head"><div><h2>Хронология</h2>'
            f'<p class="meta">Сверху: метрика по 10-минутным окнам (UTC). Снизу: по строке на задачу, полоса '
            f"от начала аномалии до её последнего окна; цвет и подпись строки показывают серьёзность. Наведите "
            f"курсор или пройдите полосы клавишей Tab, чтобы увидеть детали.</p></div>{toggle}</div>"
            f'<div class="legend">{legend}</div>'
            f'<div class="tl" id="tl"><div class="tip" id="tl-tip" role="status"></div></div>'
            f"<details><summary>Таблица данных графика по дням</summary>{_daily_table(metrics, records, by_uid)}"
            f"</details></section>")


def _daily_table(metrics, records, by_uid) -> str:
    started: dict = defaultdict(list)
    for r in records:
        started[(by_uid[r.incident_uid].start - BUCKET).date()].append(r.task_id)
    if not metrics:
        return '<p class="meta">Нет данных метрик.</p>'
    days: dict = defaultdict(lambda: {"sum": 0, "peak": None, "rps": None, "cpu": None})
    t0, s = metrics["t0"], metrics["series"]
    for i, err in enumerate(s["errors"]):
        d = days[(t0 + i * BUCKET - BUCKET).date()]   # label T covers [T-10m, T)
        if err is not None:
            d["sum"] += err
            d["peak"] = max(d["peak"] or 0, err)
        for key in ("rps", "cpu"):
            v = s[key][i]
            if v is not None:
                d[key] = max(d[key] or 0, v)
    rows = "".join(
        f'<tr><td>{day:%d.%m}</td><td class="num">{human(d["sum"])}</td><td class="num">{human(d["peak"])}</td>'
        f'<td class="num">{human(d["rps"])}</td>'
        f'<td class="num">{"—" if d["cpu"] is None else _comma(f"{d["cpu"]:.1f}") + " %"}</td>'
        f'<td>{_e(", ".join(started.get(day, [])) or "—")}</td></tr>' for day, d in sorted(days.items()))
    return ('<div class="tbl"><table><thead><tr><th>Дата</th><th class="num">Строк ошибок</th>'
            '<th class="num">Пик за 10 мин</th><th class="num">RPS, макс.</th><th class="num">CPU, макс.</th>'
            f"<th>Начались задачи</th></tr></thead><tbody>{rows}</tbody></table></div>")


def _tasks_table(records, by_uid, out_dir: Path) -> str:
    rows = []
    for rec in records:
        inc, t = by_uid[rec.incident_uid], rec.triage
        st = stem(inc)
        files = [f'<a href="{_e(quote(p))}">{label}</a>' for label, p in
                 (("задача", _file(out_dir, "tasks", st, rec.task_id)),
                  ("разбор", _file(out_dir, "postmortems", st, rec.task_id))) if p]
        votes = ""
        if len(t.votes) > 1:
            agree = sum(v == t.assignee for v in t.votes.values())
            who = "; ".join(f"{VOTERS.get(k, k)}: {v}" for k, v in t.votes.items())
            votes = f'<div class="small" title="{_e(who)}">голоса {agree} из {len(t.votes)}</div>'
        state = "" if inc.status == "resolved" else f' <span class="badge">{_e(_status(inc.status))}</span>'
        reps = (f'<span title="{_e(", ".join(r.get("start", "") for r in rec.repeats))}">{len(rec.repeats)}</span>'
                if rec.repeats else "—")
        source = SOURCES.get(t.source, t.source) + (f" · {t.model}" if t.model else "")
        cost = f" · ${t.cost_usd:.2f}" if t.cost_usd else ""
        rows.append(
            f'<tr id="task-{_e(rec.task_id)}"><td class="id">{_e(rec.task_id)}{state}</td>'
            f'<td class="title">{_e(t.title)}</td><td>{_sev(rec.severity)}</td>'
            f'<td class="nw">{_e(t.assignee)}{votes}</td>'
            f'<td class="num">{_ts(inc.start - BUCKET)}</td><td class="num">{_e(dur(ttd_minutes(inc)))}</td>'
            f'<td class="num">{_e(human(inc.impact.clients)) if inc.impact.clients else "—"}</td>'
            f'<td class="num">{reps}</td><td><div class="nw">{_e(source + cost)}</div>'
            f'<div class="small">{_verification(t)}</div></td>'
            f'<td class="files">{" · ".join(files) or "—"}</td></tr>')
    if not rows:
        return '<section class="card"><h2>Задачи</h2><p class="meta">Задач нет.</p></section>'
    return ('<section class="card"><h2>Задачи</h2><p class="meta">Начало — первое аномальное окно; TTD — от начала '
            "до оповещения; клиенты — уникальные пользователи или IP в строках ошибок инцидента. Ссылки ведут "
            'на файлы рядом с отчётом.</p><div class="tbl"><table><thead><tr><th>ID</th><th>Заголовок</th>'
            '<th>Серьёзность</th><th>Исполнитель</th><th class="num">Начало, UTC</th><th class="num">TTD</th>'
            '<th class="num">Клиенты</th><th class="num">Повторы</th><th>Анализ и сверка чисел</th>'
            f'<th>Файлы</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>')


def _eval_section(result: EvalResult, cfg) -> str:
    if not result.rows:
        return (f'<section class="card"><h2>Сверка с эталоном</h2><p class="meta">Нет разметки: '
                f"{_e(cfg.paths.gold)}.</p></section>")
    rows = []
    for r in result.rows:
        if r.task:
            task = f'<a href="#task-{_e(r.task)}">{_e(r.task)}</a>'
            role = (f'<span class="st st-ok">{_e(r.role)}</span>' if r.role_ok else
                    f'<span class="st st-bad">ожидался {_e(r.role)}, назначен {_e(r.found_role)}</span>')
        else:
            task, role = '<span class="st st-bad">не найден</span>', _e(r.role)
        rep = {True: '<span class="st st-ok">да</span>', False: '<span class="st st-bad">нет</span>', None: "—"}
        rows.append(f"<tr><td>{_e(r.gold)}</td><td>{_e(r.name)}</td><td>{task}</td><td>{role}</td>"
                    f'<td class="num">{"—" if r.ttd_min is None else r.ttd_min}</td><td>{rep[r.repeat_ok]}</td></tr>')
    found = sum(1 for r in result.rows if r.task)
    unl = ", ".join(f'<a href="#task-{_e(t)}">{_e(t)}</a>' for t in result.unlabelled) or "—"
    return ('<section class="card"><h2>Сверка с эталоном</h2>'
            f'<p class="meta">Размеченные инциденты из {_e(cfg.paths.gold.name)}: какая задача их поймала, тот ли '
            "исполнитель и сколько минут прошло от начала до оповещения.</p>"
            '<div class="tbl"><table><thead><tr><th>Эталон</th><th>Что произошло</th><th>Задача</th>'
            '<th>Исполнитель</th><th class="num">TTD, мин</th><th>Повтор в той же задаче</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div><ul class="notes">'
            f"<li>Найдено {found} из {len(result.rows)} (recall {_pct0(result.recall)}), исполнитель верный "
            f"в {_pct0(result.role_accuracy)} найденных; медианное TTD "
            f"{'—' if result.median_ttd_min is None else dur(result.median_ttd_min)}.</li>"
            f"<li>Задач всего {result.tasks}; без эталонной метки {len(result.unlabelled)}: {unl}. Это либо "
            f"ложные срабатывания, либо реальные события, которых нет в разметке.</li></ul></section>")


def _predictions(objects, result: EvalResult) -> str:
    if not result.predictions:
        return '<section class="card"><h2>Прогнозы повторов</h2><p class="meta">Прогнозов не было.</p></section>'
    rows = []
    for obj, p in zip(objects, result.predictions, strict=True):
        (ws, we), lead = p["window"], p["lead_min"]
        verdict = (f'<span class="st st-ok">сбылся: <a href="#task-{_e(p["hit_task"])}">{_e(p["hit_task"])}</a></span>'
                   if p["hit"] else '<span class="st st-na">не сбылся</span>')
        rows.append(f'<tr><td class="id"><a href="#task-{_e(p["target"])}">{_e(p["target"])}</a></td>'
                    f'<td class="num">{_ts(p["at"])}</td><td class="num">{_ts(ws)}–{we:%H:%M}</td><td>{verdict}</td>'
                    f'<td class="num">{_e(dur(lead)) if lead is not None else "—"}</td>'
                    f'<td class="small">{_e(obj.text.replace("*", ""))}</td></tr>')
    return ('<section class="card"><h2>Прогнозы повторов</h2><p class="meta">После закрытия задачи система '
            "выставляет окно риска повтора. Сбылся: в окне открылся инцидент того же исполнителя; опережение — от "
            f"прогноза до начала инцидента. Итог: {result.prediction_hits} из {len(result.predictions)}.</p>"
            '<div class="tbl"><table><thead><tr><th>Задача</th><th class="num">Прогноз сделан</th>'
            '<th class="num">Окно риска, UTC</th><th>Итог</th><th class="num">Опережение</th><th>Основание</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>')


# ---------- helpers ----------

def _file(out_dir: Path, folder: str, file_stem: str, task_id: str) -> str | None:
    """Relative link to the task's markdown; falls back to any file of the task (component may have changed)."""
    if (out_dir / folder / f"{file_stem}.md").exists():
        return f"{folder}/{file_stem}.md"
    found = sorted((out_dir / folder).glob(f"{task_id}-*.md"), key=lambda p: p.stat().st_mtime)
    return f"{folder}/{found[-1].name}" if found else None


def _verification(t) -> str:
    if t.source == "rules":
        return '<span class="st st-na">сверка не нужна</span>'
    issues = []
    if t.unverified:
        issues.append(f"не подтверждено чисел: {len(t.unverified)}")
    if t.needs_human:
        issues.append("нужен человек")
    if issues:
        return f'<span class="st st-warn" title="{_e("; ".join(t.unverified))}">{_e("; ".join(issues))}</span>'
    return '<span class="st st-ok">числа сверены</span>'


def _sev(sev: str) -> str:
    return f'<span class="sev"><i class="sw k{_e(sev[-1:])}"></i>{_e(sev)} {_e(SEV_NAMES.get(sev, ""))}</span>'


def _status(status: str) -> str:
    return {"open": "открыт", "pending": "ожидает", "blip": "всплеск"}.get(status, status)


def _plural(n: int, forms: tuple[str, str, str]) -> str:
    n10, n100 = n % 10, n % 100
    form = forms[0] if n10 == 1 and n100 != 11 else forms[1] if 2 <= n10 <= 4 and not 12 <= n100 <= 14 else forms[2]
    return f"{n} {form}"


def _pct0(x: float) -> str:
    return f"{x * 100:.0f} %"


def _comma(s: str) -> str:
    return s.replace(".", ",")


def _ms(ts: datetime) -> int:
    return int((ts.replace(tzinfo=None) - EPOCH).total_seconds() * 1000)


def _ts(ts: datetime | None, fmt: str = "%d.%m %H:%M") -> str:
    return ts.strftime(fmt) if ts else "—"


def _e(v) -> str:
    return html.escape(str(v), quote=True)


CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--wash:rgba(11,11,11,.04);--series-1:#2a78d6;
--good:#0ca30c;--warning:#fab219;--critical:#d03b3b;--sev-1:#d03b3b;--sev-2:#ec835a;--sev-3:#fab219;--sev-4:#898781;
--link:#256abf}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;
--surface:#1a1a19;--ink:#f0efec;--ink-2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);
--wash:rgba(255,255,255,.05);--series-1:#3987e5;--link:#86b6ef}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink-2:#c3c2b7;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--wash:rgba(255,255,255,.05);--series-1:#3987e5;
--link:#86b6ef}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1280px;margin:0 auto;padding:28px 16px 40px}
a{color:var(--link)}
h1{font-size:24px;font-weight:650;margin:0 0 6px}
h2{font-size:17px;font-weight:600;margin:0 0 4px}
b{font-weight:600}
.meta{color:var(--ink-2);font-size:13px;margin:0 0 4px;max-width:960px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin-top:16px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:18px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.kpi .label{color:var(--ink-2);font-size:13px}
.kpi .value{font-size:28px;font-weight:600;line-height:1.2;margin-top:4px}
.kpi .sub{color:var(--ink-2);font-size:12px;margin-top:2px}
.head{display:flex;flex-wrap:wrap;gap:12px 24px;justify-content:space-between;align-items:flex-start}
.seg{display:inline-flex;flex-wrap:wrap;border:1px solid var(--border);border-radius:8px;padding:0;margin:0;
overflow:hidden}
.seg legend{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.seg label{cursor:pointer}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg span{display:block;padding:6px 12px;font-size:13px;color:var(--ink-2)}
.seg input:checked+span{background:var(--wash);color:var(--ink);font-weight:600}
.seg input:focus-visible+span{outline:2px solid var(--series-1);outline-offset:-2px}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12px;color:var(--ink-2);margin:12px 0 4px}
.sw{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-2px}
.sw.neutral{background:var(--ink-2)}
.sw.thin{height:6px;border-radius:2px;vertical-align:1px}
.k1{background:var(--sev-1)}.k2{background:var(--sev-2)}.k3{background:var(--sev-3)}.k4{background:var(--sev-4)}
.tl{position:relative;overflow-x:auto;margin-top:6px}
.tl svg{display:block}
.tl .grid{stroke:var(--grid);stroke-width:1;shape-rendering:crispEdges}
.tl .axis{stroke:var(--axis);stroke-width:1;shape-rendering:crispEdges}
.tl .tick{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}
.tl .row-id{fill:var(--ink);font-size:12px;font-weight:600}
.tl .row-sev{fill:var(--ink-2);font-size:11px}
.tl .zebra{fill:var(--wash)}
.tl .area{fill:var(--series-1);fill-opacity:.10}
.tl .line{fill:none;stroke:var(--series-1);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.tl .cross{stroke:var(--ink-2);stroke-width:1;shape-rendering:crispEdges}
.tl .dot{fill:var(--series-1);stroke:var(--surface);stroke-width:2}
.tl .band{fill-opacity:.16}
.tl .bar{cursor:pointer;outline:none}
.tl .bar.on rect,.tl .bar:focus-visible rect{stroke:var(--ink);stroke-width:1.5}
.tl .bar .life{opacity:.7}
.tl .c1{fill:var(--sev-1)}.tl .c2{fill:var(--sev-2)}.tl .c3{fill:var(--sev-3)}.tl .c4{fill:var(--sev-4)}
.tip{position:absolute;display:none;pointer-events:none;z-index:2;max-width:340px;background:var(--surface);
border:1px solid var(--border);border-radius:8px;box-shadow:0 6px 20px rgba(0,0,0,.14);padding:8px 10px;
font-size:12px;color:var(--ink-2)}
.tip .strong{font-size:14px;font-weight:600;color:var(--ink)}
.tip .title{color:var(--ink);margin:2px 0 4px}
.tip .hdr{margin-top:6px;color:var(--ink)}
.tip .k{display:inline-block;width:12px;height:3px;border-radius:2px;margin-right:6px;vertical-align:middle}
details{margin-top:12px}
summary{cursor:pointer;color:var(--ink-2);font-size:13px}
.tbl{overflow-x:auto;margin-top:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;font-weight:600;color:var(--ink-2);padding:8px;border-bottom:1px solid var(--axis);
white-space:nowrap;vertical-align:bottom}
td{padding:8px;border-bottom:1px solid var(--grid);vertical-align:top}
tbody tr:hover{background:var(--wash)}
tr:target{background:var(--wash);outline:2px solid var(--series-1);outline-offset:-2px}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.id{font-weight:600;white-space:nowrap}
td.files,.nw,.st{white-space:nowrap}
td.title{min-width:220px}
.small{font-size:12px;color:var(--ink-2)}
td.small{min-width:280px}
.sev{white-space:nowrap}
.badge{display:inline-block;font-size:11px;font-weight:600;border:1px solid var(--axis);border-radius:6px;
padding:0 5px;margin-left:4px}
.st::before{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;
margin-right:6px;font-size:11px;font-weight:700;vertical-align:-3px}
.st-ok::before{content:"✓";background:var(--good);color:#fff}
.st-bad::before{content:"✕";background:var(--critical);color:#fff}
.st-warn::before{content:"!";background:var(--warning);color:#0b0b0b}
.st-na::before{content:"–";background:var(--wash);color:var(--ink-2);border:1px solid var(--axis)}
.notes{margin:12px 0 0;padding-left:18px;color:var(--ink-2);font-size:13px}
footer{margin-top:24px;color:var(--ink-2);font-size:12px;word-break:break-all}
"""

JS = r"""
(() => {
  const D = JSON.parse(document.getElementById('argus-data').textContent);
  const wrap = document.getElementById('tl'), tip = document.getElementById('tl-tip');
  if (!wrap) return;
  const NS = 'http://www.w3.org/2000/svg';
  const nf = new Intl.NumberFormat('ru-RU');
  const cf = new Intl.NumberFormat('ru-RU', {notation: 'compact', maximumFractionDigits: 1});
  const p2 = n => String(n).padStart(2, '0');
  const day = ms => { const d = new Date(ms); return p2(d.getUTCDate()) + '.' + p2(d.getUTCMonth() + 1); };
  const when = ms => {
    const d = new Date(ms);
    return day(ms) + ' ' + p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes());
  };
  const sevN = s => s.slice(-1);
  const mk = (tag, attrs, parent) => {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  };
  const fmt = (s, v) => v == null ? 'нет данных'
    : s.key === 'cpu' ? v.toFixed(1).replace('.', ',') + ' %' : nf.format(Math.round(v));
  const tick = (s, v) => s.key === 'cpu' ? v + ' %' : cf.format(v);
  const nice = x => { const p = Math.pow(10, Math.floor(Math.log10(x))), m = x / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; };
  let key = D.series.length ? D.series[0].key : null, lastW = -1;

  function tipShow(rows, px, py, H) {
    tip.replaceChildren();
    for (const [cls, text, sev] of rows) {
      const line = document.createElement('div');
      if (cls) line.className = cls;
      if (sev) { const k = document.createElement('span'); k.className = 'k k' + sevN(sev); line.appendChild(k); }
      line.appendChild(document.createTextNode(text));
      tip.appendChild(line);
    }
    tip.style.display = 'block';
    const w = tip.offsetWidth, h = tip.offsetHeight;
    const minX = wrap.scrollLeft + 4, maxX = wrap.scrollLeft + wrap.clientWidth - w - 4;
    let x = px + 16;
    if (x > maxX) x = px - w - 16;
    tip.style.left = Math.max(minX, x) + 'px';
    tip.style.top = Math.max(4, Math.min(H - h - 4, py - h / 2)) + 'px';
  }

  function draw() {
    lastW = wrap.clientWidth;
    const old = wrap.querySelector('svg');
    if (old) old.remove();
    const W = Math.max(wrap.clientWidth, 720), L = 116, R = 16, T = 10, MH = 210, GAP = 16, RH = 20, AX = 26;
    const tasks = D.tasks, gT = T + MH + GAP, gH = Math.max(tasks.length, 1) * RH, H = gT + gH + AX;
    const PW = W - L - R, t0 = D.range[0], t1 = D.range[1], span = Math.max(t1 - t0, 1);
    const X = t => L + (t - t0) / span * PW;
    const s = D.series.find(q => q.key === key);
    const svg = mk('svg', {width: W, height: H, role: 'group',
      'aria-label': 'Хронология: ' + (s ? s.label : 'метрики') + ' и задачи по строкам'});
    wrap.insertBefore(svg, tip);
    const note = (x, y, text) => {
      mk('text', {x, y, class: 'tick', 'text-anchor': 'middle'}, svg).textContent = text;
    };
    tasks.forEach((tk, r) => {
      if (r % 2) mk('rect', {x: 0, y: gT + r * RH, width: W, height: RH, class: 'zebra'}, svg);
    });

    let Y = null;
    if (s) {
      let vmax = 1;
      for (const v of s.values) if (v != null && v > vmax) vmax = v;
      const ticks = [];
      if (s.scale === 'log') {
        const top = Math.pow(10, Math.ceil(Math.log10(Math.max(vmax, 10))));
        Y = v => T + MH - Math.log10(Math.max(v, 1)) / Math.log10(top) * MH;
        for (let v = 1; v <= top; v *= 10) ticks.push(v);
      } else {
        const st = nice(vmax / 4), top = Math.ceil(vmax / st) * st;
        Y = v => T + MH - v / top * MH;
        for (let i = 0; i * st <= top + st / 2; i++) ticks.push(i * st);
      }
      ticks.forEach((v, i) => {
        const y = Math.round(Y(v)) + .5;
        mk('line', {x1: L, x2: L + PW, y1: y, y2: y, class: i ? 'grid' : 'axis'}, svg);
        mk('text', {x: L - 8, y: y + 4, class: 'tick', 'text-anchor': 'end'}, svg).textContent = tick(s, v);
      });
    }
    const DAY = 864e5, every = PW / (span / DAY) < 46 ? 2 : 1;
    for (let d = Math.ceil(t0 / DAY) * DAY, i = 0; d <= t1; d += DAY, i++) {
      const x = Math.round(X(d)) + .5;
      mk('line', {x1: x, x2: x, y1: T, y2: gT + gH, class: 'grid'}, svg);
      if (i % every === 0) mk('text', {x, y: H - 8, class: 'tick', 'text-anchor': 'middle'}, svg).textContent = day(d);
    }
    const band = mk('rect', {x: 0, y: T, width: 0, height: MH, class: 'band', visibility: 'hidden'}, svg);

    if (s) {  // one point per ~2px: max for error bursts (keeps spikes), mean for gauges
      const n = s.values.length, per = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(PW / 2))));
      let line = '', area = '', seg = [];
      const flush = () => {
        if (seg.length) {
          const d = 'M' + seg.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join('L');
          line += d;
          const a = seg[0][0].toFixed(1), b = seg[seg.length - 1][0].toFixed(1);
          area += d + 'L' + b + ',' + (T + MH) + 'L' + a + ',' + (T + MH) + 'Z';
        }
        seg = [];
      };
      for (let i = 0; i < n; i += per) {
        const j1 = Math.min(n, i + per);
        let cnt = 0, sum = 0, mx = -Infinity;
        for (let j = i; j < j1; j++) { const v = s.values[j]; if (v != null) { cnt++; sum += v; if (v > mx) mx = v; } }
        if (!cnt) { flush(); continue; }
        seg.push([X(D.t0 + (i + j1 - 1) / 2 * D.step), Y(s.key === 'errors' ? mx : sum / cnt)]);
      }
      flush();
      mk('path', {d: area, class: 'area'}, svg);
      mk('path', {d: line, class: 'line'}, svg);
    } else {
      note(L + PW / 2, T + MH / 2, 'Нет данных метрик');
    }

    tasks.forEach((tk, r) => {
      const y0 = gT + r * RH, ym = y0 + RH / 2 + 4;
      mk('text', {x: 8, y: ym, class: 'row-id'}, svg).textContent = tk.id;
      mk('text', {x: 70, y: ym, class: 'row-sev'}, svg).textContent = tk.sev;
      for (const sp of tk.spans) {  // lifeline over the whole incident, a bar per window of real activity
        const h = sp.rep ? 6 : 12, yb = y0 + (RH - h) / 2;
        sp.el = mk('g', {class: 'bar c' + sevN(tk.sev), tabindex: 0,
          'aria-label': tk.id + ', ' + tk.sev + (sp.rep ? ', повтор' : '') + ', начало ' + when(sp.s) + ' UTC, '
            + tk.title}, svg);
        if (sp.segs.length > 1) {
          mk('rect', {x: X(sp.s).toFixed(1), y: y0 + RH / 2 - 1, width: Math.max(X(sp.e) - X(sp.s), 1).toFixed(1),
            height: 2, class: 'life'}, sp.el);
        }
        for (const [a, b] of sp.segs) {
          const x0 = X(a), w = Math.max(X(b) - x0, 3), rx = Math.min(sp.rep ? 2 : 3, w / 2);
          mk('rect', {x: x0.toFixed(1), y: yb, width: w.toFixed(1), height: h, rx}, sp.el);
        }
        sp.el.addEventListener('focus', () => {
          const b = sp.el.getBoundingClientRect(), wr = wrap.getBoundingClientRect();
          showSpan(tk, sp, b.right - wr.left + wrap.scrollLeft, b.top - wr.top + b.height / 2);
        });
        sp.el.addEventListener('blur', hide);
      }
    });
    if (!tasks.length) note(L + PW / 2, gT + RH / 2 + 4, 'Задач нет');
    const cross = mk('line', {y1: T, y2: gT + gH, class: 'cross', visibility: 'hidden'}, svg);
    const dot = mk('circle', {r: 4, class: 'dot', visibility: 'hidden'}, svg);
    let on = null;

    function hide() {
      tip.style.display = 'none';
      for (const n of [cross, dot, band]) n.setAttribute('visibility', 'hidden');
      if (on) { on.classList.remove('on'); on = null; }
    }
    function showSpan(tk, sp, px, py) {
      hide();
      band.setAttribute('x', X(sp.s));
      band.setAttribute('width', Math.max(X(sp.e) - X(sp.s), 4));
      band.setAttribute('class', 'band c' + sevN(tk.sev));
      band.setAttribute('visibility', 'visible');
      on = sp.el; on.classList.add('on');
      const rows = [['strong', tk.id + ' · ' + tk.sev + ' ' + (D.sevNames[tk.sev] || '') + (sp.rep ? ' · повтор' : '')],
        ['title', tk.title], ['', 'Исполнитель: ' + tk.who], ['', 'Начало: ' + when(sp.s) + ' UTC'],
        ['', 'Оповещение: ' + (sp.d ? when(sp.d) : '—') + ' · TTD ' + sp.ttd],
        ['', 'Последнее аномальное окно: ' + when(sp.e)]];
      if (sp.segs.length > 1) rows.push(['', 'Прерывистый: ' + sp.segs.length + ' окон активности']);
      if (sp.clients) rows.push(['', 'Клиенты: ' + sp.clients]);
      if (sp.rep && sp.sev !== tk.sev) rows.push(['', 'Серьёзность этого эпизода: ' + sp.sev]);
      tipShow(rows, px, py, H);
    }
    function showCross(mx, px, py) {
      hide();
      if (!s) return;
      const i = Math.max(0, Math.min(s.values.length - 1, Math.round((t0 + (mx - L) / PW * span - D.t0) / D.step)));
      const tt = D.t0 + i * D.step, xx = Math.round(X(tt)) + .5, v = s.values[i];
      cross.setAttribute('x1', xx); cross.setAttribute('x2', xx); cross.setAttribute('visibility', 'visible');
      if (v != null) {
        dot.setAttribute('cx', xx); dot.setAttribute('cy', Y(v)); dot.setAttribute('visibility', 'visible');
      }
      const rows = [['strong', fmt(s, v)], ['', s.label], ['', '10 минут до ' + when(tt) + ' UTC']];
      const act = tasks.filter(tk => tk.spans.some(sp => sp.segs.some(([a, b]) => a < tt && tt <= b)));
      if (act.length) rows.push(['hdr', 'Идут инциденты:']);
      for (const tk of act) rows.push(['', tk.id + ' · ' + tk.sev + ' · ' + tk.who, tk.sev]);
      tipShow(rows, px, py, H);
    }
    svg.addEventListener('pointermove', ev => {
      const r = svg.getBoundingClientRect(), wr = wrap.getBoundingClientRect();
      const mx = ev.clientX - r.left, my = ev.clientY - r.top;
      const px = ev.clientX - wr.left + wrap.scrollLeft, py = ev.clientY - wr.top;
      if (mx < L || mx > L + PW || my > gT + gH) { hide(); return; }
      if (my >= gT) {
        const tk = tasks[Math.floor((my - gT) / RH)];
        let best = null, bd = 10;
        for (const sp of (tk ? tk.spans : [])) {
          const a = X(sp.s), b = a + Math.max(X(sp.e) - a, 4), d = mx < a ? a - mx : mx > b ? mx - b : 0;
          if (d <= bd) { bd = d; best = sp; }
        }
        if (best) { showSpan(tk, best, px, py); return; }
      }
      showCross(mx, px, py);
    });
    svg.addEventListener('pointerleave', hide);
  }

  document.querySelectorAll('input[name="tl-series"]').forEach(inp =>
    inp.addEventListener('change', () => { key = inp.value; draw(); }));
  if (window.ResizeObserver) new ResizeObserver(() => { if (wrap.clientWidth !== lastW) draw(); }).observe(wrap);
  else window.addEventListener('resize', draw);
  draw();
})();
"""
