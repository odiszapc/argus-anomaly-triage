from datetime import datetime

from argus.evals import Detection, Gold, evaluate

D = datetime


def test_match_by_overlap_and_role():
    gold = [Gold("G1", "valkey", D(2026, 9, 2, 11, 20), D(2026, 9, 2, 19, 10), "DBA"),
            Gold("G1b", "valkey again", D(2026, 9, 3, 6, 20), D(2026, 9, 3, 10, 0), "DBA", repeat_of="G1"),
            Gold("G5", "bot", D(2026, 9, 6, 1, 30), D(2026, 9, 6, 1, 45), "Security Lead")]
    detections = [
        Detection("ARG-011", "DBA", D(2026, 9, 2, 11, 20), D(2026, 9, 2, 11, 40), D(2026, 9, 2, 20, 0), None),
        Detection("ARG-011", "DBA", D(2026, 9, 3, 6, 20), D(2026, 9, 3, 6, 30), D(2026, 9, 3, 11, 0), "ARG-011"),
        Detection("ARG-020", "Backend Lead", D(2026, 9, 5, 10, 0), D(2026, 9, 5, 10, 10), D(2026, 9, 5, 11, 0), None),
    ]
    r = evaluate(gold, detections, [])
    rows = {row.gold: row for row in r.rows}
    assert rows["G1"].task == "ARG-011" and rows["G1"].ttd_min == 20 and rows["G1"].role_ok
    assert rows["G1b"].repeat_ok and rows["G1b"].task == "ARG-011"
    assert rows["G5"].task is None
    assert (r.recall, r.tasks, r.unlabelled) == (2 / 3, 2, ["ARG-020"])


def test_gold_with_component_and_country_matches_only_those():
    gold = [Gold("G4", "brazil", D(2026, 9, 3, 9, 0), D(2026, 9, 4, 2, 0), "SEO Specialist", country="BR"),
            Gold("G7", "rps", D(2026, 8, 24, 11, 10), D(2026, 9, 7, 11, 10), "PaaS Engineer", component="observability")]
    detections = [
        Detection("ARG-007", "SEO Specialist", D(2026, 9, 3, 1, 10), D(2026, 9, 3, 2, 10), D(2026, 9, 3, 9, 20), None,
                  component="country_traffic", country="CN"),
        Detection("ARG-012", "SEO Specialist", D(2026, 9, 3, 9, 20), D(2026, 9, 3, 10, 20), D(2026, 9, 4, 8, 0), None,
                  component="country_traffic", country="BR"),
        Detection("ARG-001", "PaaS Engineer", D(2026, 8, 24, 16, 30), D(2026, 8, 24, 17, 0), D(2026, 8, 24, 19, 0), None,
                  component="capacity"),
        Detection("ARG-005", "PaaS Engineer", D(2026, 8, 24, 12, 30), D(2026, 8, 25, 9, 0), D(2026, 8, 28, 0, 0), None,
                  component="observability"),
    ]
    rows = {r.gold: r for r in evaluate(gold, detections, []).rows}
    assert (rows["G4"].task, rows["G7"].task) == ("ARG-012", "ARG-005")
