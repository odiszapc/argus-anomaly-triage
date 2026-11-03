"""What a task says about an incident. The LLM analyst fills it; `fallback_triage` writes it from rules
and numbers alone, so the pipeline works with no model at all (CI, offline, outages of the LLM)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .correlate import Incident
from .render.fmt import dur, human, pct
from .routing import Router
from .timeutil import fmt_short

NEXT_STEPS: dict[str, list[str]] = {
    "cache": ["Проверить состояние узлов Valkey: рестарты, failover, использование памяти, evictions",
              "Сверить топологию кластера и карту слотов у клиентов (MOVED/CROSSSLOT)",
              "Оценить нагрузку на БД из-за промахов кэша"],
    "database": ["Проверить состояние репликасета: выборы primary, лаг реплик, сетевые таймауты",
                 "Посмотреть медленные запросы и пул соединений драйвера",
                 "Проверить сетевую связность приложения с узлами БД"],
    "infra_dns": ["Проверить DNS/service discovery в кластере и наличие сервиса-адресата",
                  "Сверить конфигурацию окружения последней выкладки"],
    "app_lock": ["Сопоставить начало роста с выкладками", "Найти ключи/ресурсы с наибольшим ожиданием блокировки",
                 "Проверить синхронное истечение TTL (jitter, early refresh)"],
    "app_bug": ["Найти выкладку, после которой появились ошибки", "Собрать стектрейсы и затронутые эндпоинты"],
    "external": ["Проверить статус и изменения API внешнего провайдера",
                 "Убедиться, что сбой не блокирует запрос пользователя"],
    "upstream": ["Найти внутренний сервис с наибольшей долей таймаутов", "Проверить его latency, рестарты и выкладки"],
    "app_errors": ["Собрать стектрейсы и сопоставить с выкладками"],
    "capacity": ["Сравнить нагрузку с запасом мощности, проверить работу автоскейлинга",
                 "Проверить, не вызваны ли пики ретраями клиентов"],
    "country_traffic": ["Проверить позиции и индексацию в поиске для страны", "Сверить с маркетинговыми кампаниями",
                        "Проверить долю бот-трафика из страны"],
    "observability": ["Проверить дубли scrape targets и реплики экспортера RPS",
                      "Сверить скачки с выкладками и рестартами подов"],
    "abuse": ["Заблокировать или ограничить ASN/подсети источника на WAF", "Проверить, какие эндпоинты атакуются",
              "Оценить, есть ли успешные запросы от этих IP"],
}


@dataclass
class Hypothesis:
    cause: str
    evidence: str
    confidence: str  # высокая | средняя | низкая


@dataclass
class Triage:
    title: str
    summary: str
    symptoms: list[str]
    hypotheses: list[Hypothesis]
    assignee: str
    assignee_reason: str
    next_steps: list[str]
    impact_note: str = ""
    source: str = "rules"              # rules | claude | ollama
    model: str = ""
    queries: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)
    votes: dict[str, str] = field(default_factory=dict)
    needs_human: bool = False
    arbiter_note: str = ""
    cost_usd: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Triage:
        d = dict(d)
        d["hypotheses"] = [Hypothesis(**h) for h in d.get("hypotheses", [])]
        return cls(**d)


def _title(incident: Incident, router: Router) -> str:
    comp = router.get(incident.component)
    logs = incident.log_signals()
    if incident.component == "country_traffic":
        s = next(x for x in incident.signals.values() if x.kind == "country_shift")
        verb = "вырос" if s.attrs.get("direction") == "up" else "упал"
        return f"Трафик из {s.key} {verb} в {s.value / s.baseline:.1f} раза относительно обычного" if s.baseline else \
            f"Аномалия трафика из {s.key}"
    if incident.component == "observability":
        return "Метрика RPS: повторяющиеся скачки без подтверждения CPU и трафиком по странам"
    if incident.component == "abuse" and incident.bot:
        return f"Автоматизированный трафик через {incident.bot.top_isp}: {pct(incident.bot.top_share)} запросов"
    if incident.component == "capacity":
        return "Пиковая нагрузка: рост RPS и таймауты внутренних API"
    own = [s for s in logs if router.same_problem(router.component_of(s).name, incident.component)]
    if own or logs:
        return f"{comp.title}: всплеск «{(own or logs)[0].label[:70]}»"
    return comp.title


def symptom_lines(incident: Incident) -> list[str]:
    lines = []
    for s in incident.log_signals()[:5]:
        minutes = int((s.end - s.start).total_seconds() // 60) + 10
        new = " (новый тип ошибки)" if s.attrs.get("new_template") else ""
        lines.append(f"«{s.label[:90]}»{new}: {human(s.total)} строк за {dur(minutes)}, "
                     f"пик {human(s.value)} за 10 мин при норме {human(s.baseline)}")
    for s in incident.signals.values():
        if s.kind == "cpu_high":
            lines.append(f"CPU до {s.value:.0f} % (обычно {s.baseline:.0f} %)")
        elif s.kind == "rps_shift":
            lines.append(f"RPS {human(s.value)} при обычных {human(s.baseline)} ({s.value / s.baseline - 1:+.0%})")
        elif s.kind == "traffic_shift":
            lines.append(f"Суммарный трафик по странам {s.value / s.baseline - 1:+.0%} к обычному")
        elif s.kind == "country_shift":
            lines.append(f"Трафик из {s.key}: {human(s.value)} хитов/с при обычных {human(s.baseline)} "
                         f"({s.value / s.baseline - 1:+.0%}), {fmt_short(s.start)} – {fmt_short(s.end)}")
    if incident.component == "observability":
        lines.append("Скачки одиночные (одна точка), только в будни; CPU и счётчик по странам в те же минуты ровные")
    if incident.impact.peak_error_rate:
        lines.append(f"Пиковая доля ошибок: {pct(incident.impact.peak_error_rate)} запросов за 10 минут")
    return lines


def fallback_triage(incident: Incident, router: Router) -> Triage:
    comp = router.get(incident.component)
    hypotheses = [Hypothesis(h, "типичная причина для этого класса сигналов", "средняя" if i == 0 else "низкая")
                  for i, h in enumerate(comp.hypotheses)]
    reason = f"Правило маршрутизации: компонент «{comp.title}» → {comp.role}"
    if incident.component == "abuse" and incident.bot:
        from .detect.security import is_bot_like
        reason += f". Признаки бота: {is_bot_like(incident.bot)[1]}"
    elif incident.component == "capacity":
        reason += ". Ошибки внутренних API совпали с ростом нагрузки, причины в БД/кэше/коде не видно"
    logs = incident.log_signals()
    lead = f"Первым сигналом стал «{logs[-1].label[:60]}»." if logs else ""
    summary = (f"{_title(incident, router)}. Начало {fmt_short(incident.start)} UTC. {lead} "
               f"Затронуто ≈{human(incident.impact.clients)} клиентов.").replace("  ", " ")
    return Triage(title=_title(incident, router), summary=summary, symptoms=symptom_lines(incident),
                  hypotheses=hypotheses, assignee=comp.role, assignee_reason=reason,
                  next_steps=NEXT_STEPS.get(incident.component, NEXT_STEPS["app_errors"]),
                  impact_note=IMPACT_NOTE, votes={"rules": comp.role})


IMPACT_NOTE = ("Клиент = user_id, для анонимных запросов — IP. В лог попадают только ошибки, поэтому это нижняя "
               "граница числа людей, у которых что-то сломалось; доля ошибок считается к RPS без семплирования.")
