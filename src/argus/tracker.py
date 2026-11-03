"""A task tracker made of markdown files: tasks/ARG-###-*.md with YAML front matter.

`list()` reads the front matter back, which is how dedup checks for an existing task before creating
one; swapping in Jira/YouTrack means implementing the same four methods over their API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from .correlate import Incident
from .render.task import render_postmortem, render_task, stem
from .triage import Triage

ID_RE = re.compile(r"^ARG-(\d{3,})")


@dataclass
class TaskRef:
    id: str
    path: Path
    postmortem: Path


class Tracker:
    def __init__(self, out_dir: Path, url_template: str = "https://tracker.example.com/browse/{id}"):
        self.tasks_dir, self.pm_dir = Path(out_dir) / "tasks", Path(out_dir) / "postmortems"
        self.url_template = url_template

    def next_id(self) -> str:
        nums = [int(m.group(1)) for p in self.tasks_dir.glob("ARG-*.md") if (m := ID_RE.match(p.name))]
        return f"ARG-{max(nums, default=0) + 1:03d}"

    def url(self, task_id: str) -> str:
        return self.url_template.format(id=task_id)

    def create(self, incident: Incident, triage: Triage, history: list[tuple[datetime, str]]) -> TaskRef:
        incident.task_id = self.next_id()
        return self.write(incident, triage, history)

    def write(self, incident: Incident, triage: Triage, history: list[tuple[datetime, str]],
              repeats: list[dict] | None = None, related: list[str] | None = None,
              prediction: str | None = None, severity: str | None = None) -> TaskRef:
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        self.pm_dir.mkdir(parents=True, exist_ok=True)
        name = stem(incident) + ".md"
        task_path, pm_path = self.tasks_dir / name, self.pm_dir / name
        task_path.write_text(render_task(incident, triage, history, repeats, related, severity))
        pm_path.write_text(render_postmortem(incident, triage, history, prediction, severity))
        return TaskRef(incident.task_id, task_path, pm_path)

    def list(self) -> list[dict]:
        out = []
        for path in sorted(self.tasks_dir.glob("ARG-*.md")):
            text = path.read_text()
            if text.startswith("---"):
                front = yaml.safe_load(text.split("---", 2)[1]) or {}
                front["path"] = str(path)
                out.append(front)
        return out
