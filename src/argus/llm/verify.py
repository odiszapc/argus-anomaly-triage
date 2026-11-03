"""Every number the model writes must be backed by data it was shown or queried.

Numbers are read in the forms tasks use ("8,56 млн", "17,5 тыс.", "4,0 %", "1 234") and matched with
a tolerance that follows the precision they were written with. Times, dates, years, small counts and
quoted log text are not claims and are skipped.
"""

from __future__ import annotations

import json
import re

UNITS = {"млрд": 1e9, "млн": 1e6, "тыс.": 1e3, "тыс": 1e3, "%": 1.0}
_DATE_NOT_DECIMAL = r"\b\d{1,2}\.\d{1,2}(\.\d{2,4})?\b(?![ \u00a0]?(?:млрд|млн|тыс|%))"  # 02.09, but not 8.56 млн
_SKIP = [re.compile(p) for p in (r"«[^»]*»", r'"[^"]*"', r"`[^`]*`", r"\b\d{1,2}:\d{2}(:\d{2})?\b",
                                 r"\b\d{4}-\d{2}-\d{2}\b", _DATE_NOT_DECIMAL,
                                 r"\b(SEV|ARG|P)-?\d+\b", r"\b[A-Za-z_]+\d+[A-Za-z_\d]*\b")]
_NUM = re.compile(r"(?<![\w.,])(\d{1,3}(?:[   ]\d{3})+|\d+)(?:[.,](\d+))?(?:[  ]?(млрд|млн|тыс\.?|%))?")


def extract_numbers(text: str) -> list[tuple[str, float]]:
    for pattern in _SKIP:
        text = pattern.sub(" ", text)
    out = []
    for m in _NUM.finditer(text):
        whole, frac, unit = m.group(1), m.group(2), m.group(3)
        value = float(re.sub(r"\D", "", whole) + ("." + frac if frac else ""))
        out.append((m.group(0).strip(), value * UNITS.get(unit or "", 1.0) if unit != "%" else value))
    return out


def _tolerance(raw: str, value: float) -> float:
    frac = re.search(r"[.,](\d+)", raw)
    decimals = len(frac.group(1)) if frac else 0
    unit = next((u for u in UNITS if raw.endswith(u)), "")
    scale = UNITS.get(unit, 1.0) if unit != "%" else 1.0
    return 0.5 * 10 ** -decimals * scale + 0.015 * abs(value)


def verify_numbers(texts: list[str], known: list[float]) -> list[str]:
    candidates = [abs(k) for k in known] + [abs(k) * 100 for k in known if abs(k) <= 1.0]
    unverified = []
    for text in texts:
        for raw, value in extract_numbers(text):
            has_unit = any(raw.endswith(u) for u in UNITS)
            if not has_unit and (value <= 10 or 2020 <= value <= 2030):
                continue  # small counts and years; never a percentage or a magnitude
            tol = _tolerance(raw, value)
            if not any(abs(value - k) <= tol for k in candidates):
                unverified.append(raw)
    return unverified


def known_numbers(evidence: dict, tool_outputs: list[str]) -> list[float]:
    nums: list[float] = []

    def walk(x):
        if isinstance(x, bool):
            return
        if isinstance(x, (int, float)):
            nums.append(float(x))
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(json.loads(json.dumps(evidence, default=str)))
    cell = re.compile(r"-?\d+(?:\.\d+)?(?:e[+-]?\d+)?")
    for out in tool_outputs:  # numeric cells only: timestamps, IPs and ids are not evidence for a number
        nums += [float(c) for line in out.splitlines() for c in line.split(",") if cell.fullmatch(c.strip())]
    return nums
