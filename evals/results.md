| Эталон | Что | Задача | Роль ожид./найдена | TTD, мин | Повтор в той же задаче |
|---|---|---|---|---|---|
| G1 | Valkey cache cluster failure (LOADING, MOVED, REST timeout storm, CPU 96 %) | ARG-011 | DBA / DBA ✓ | 10 |  |
| G1b | Valkey failure comes back at the morning ramp | ARG-011 | DBA / DBA ✓ | 10 | да |
| G2 | MongoDB connectivity loss (monitor timeouts, then "Topology is closed") | ARG-003 | DBA / DBA ✓ | 30 |  |
| G2b | MongoDB topology closed again | ARG-003 | DBA / DBA ✓ | 30 | да |
| G3 | Lock-wait regression ("Timeout 0 wait exceeded" x200-500, 15-minute bursts) | ARG-006 | Backend Lead / Backend Lead ✓ | 0 |  |
| G4 | Brazil traffic +60-95 % for 17 hours | ARG-012 | SEO Specialist / SEO Specialist ✓ | 140 |  |
| G5 | Bot through rotating proxies (RapidSeedbox), "Adapter failure" burst | ARG-014 | Security Lead / Security Lead ✓ | 20 |  |
| G6 | Timeouts at the evening traffic peak | ARG-001 | PaaS Engineer / PaaS Engineer ✓ | 0 |  |
| G7 | RPS metric doublings not confirmed by CPU or per-country hits | ARG-005 | PaaS Engineer / PaaS Engineer ✓ | 1350 |  |

- Найдено эталонных инцидентов: **9 из 9** (recall 100%), исполнитель верный в 100% найденных
- Медианное время до оповещения: 20 мин
- Задач всего: 14; без эталонной метки: 7 (ARG-002, ARG-004, ARG-007, ARG-008, ARG-009, ARG-010, ARG-013)
- Прогнозы: 2 из 4 сбылись
  - ARG-003 26.08 17:30 → окно 27.08 04:30–08:30: не сбылся
  - ARG-009 31.08 16:00 → окно 01.09 04:40–08:40: сбылся (ARG-009, за 890 мин)
  - ARG-010 02.09 10:10 → окно 02.09 11:30–15:30: не сбылся
  - ARG-011 02.09 23:30 → окно 03.09 05:00–09:00: сбылся (ARG-011, за 400 мин)
