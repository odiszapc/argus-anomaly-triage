import duckdb

from argus.templates import sql_template_expr, template_id, template_of

SAMPLES = [
    ("Rest error: Operation timed out after 1000 milliseconds with 0 bytes received",
     "Rest error: Operation timed out after <N> milliseconds with <N> bytes received"),
    ("MOVED 1234 10.1.2.3:6379", "MOVED <N> <IP>"),
    ('Value "abc"is not valid for the enum "Kind"', 'Value "<S>"is not valid for the enum "<S>"'),
    ("Property 'foo' assignment error", "Property '<S>' assignment error"),
    ("job 123e4567-e89b-12d3-a456-426614174000 failed", "job <UUID> failed"),
    ("token deadbeefdeadbeef01 rejected", "token <HEX> rejected"),
]


def test_template_masks():
    for message, expected in SAMPLES:
        assert template_of(message) == expected


def test_sql_and_python_masks_agree():
    con = duckdb.connect()
    for message, _ in SAMPLES:
        tpl, tid = con.execute(f"SELECT {sql_template_expr('$1')}, left(md5({sql_template_expr('$1')}), 10)",
                               [message]).fetchone()
        assert tpl == template_of(message)
        assert tid == template_id(tpl)
