---
name: tune-detection
description: Use when changing Argus thresholds, detectors, routing rules or incident lifecycle settings, or when a false positive or a missed incident is reported.
---

# Change detection without breaking it

1. Reproduce first: a failing test on a synthetic series or synthetic signals
   (`tests/test_detectors.py`, `tests/test_correlate.py`) that shows the false positive or the miss.
2. Baseline: `make replay-offline eval` and save the score card.
3. Make the smallest change: `config/argus.yaml` (thresholds), `config/routing.yaml` (owners, patterns),
   or the detector/correlation code. Keep detectors causal.
4. `make test` and `make replay-offline eval` again. Compare recall, assignee accuracy, median TTD and
   the list of tasks without a label. A change that adds a task without a label needs a reason.
5. Commit with the before/after numbers in the message. Do not edit `evals/gold.yaml` to fit a change.
