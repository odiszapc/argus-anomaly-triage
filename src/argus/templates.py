"""Log message → template. One list of masks feeds both DuckDB (ingest) and Python (tests, tools).

Why masks and not Drain3: on this export the masks give ~440 stable templates and run inside DuckDB
over 35M lines in seconds; a per-line Python parser would take minutes and add no precision.
"""

from __future__ import annotations

import hashlib
import re

MAX_LEN = 300

# (pattern, replacement), applied in order. Patterns use the subset shared by RE2 and Python `re`.
MASKS: list[tuple[str, str]] = [
    (r'"[^"]{1,200}"', '"<S>"'),
    (r"'[^']{1,200}'", "'<S>'"),
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", "<IP>"),
    (r"\b[0-9a-fA-F]{16,}\b", "<HEX>"),
    (r"\d+", "<N>"),
]

_COMPILED = [(re.compile(p), r) for p, r in MASKS]


def template_of(message: str | None) -> str:
    text = (message or "")[:MAX_LEN]
    for pattern, repl in _COMPILED:
        text = pattern.sub(repl, text)
    return text


def template_id(template: str) -> str:
    return hashlib.md5(template.encode("utf-8")).hexdigest()[:10]


def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def sql_template_expr(column: str) -> str:
    """DuckDB expression computing the same template as `template_of`."""
    expr = f"left(coalesce({column}, ''), {MAX_LEN})"
    for pattern, repl in MASKS:
        expr = f"regexp_replace({expr}, {_sql_str(pattern)}, {_sql_str(repl)}, 'g')"
    return expr
