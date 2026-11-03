"""config/routing.yaml → components (owner role, family, cause/symptom, starting hypotheses)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import REPO_ROOT
from .model import Signal

DEFAULT_ROUTING = REPO_ROOT / "config" / "routing.yaml"
FALLBACK_COMPONENT = "app_errors"


@dataclass
class Component:
    name: str
    title: str
    role: str
    family: str
    kind: str                                   # cause | symptom
    hypotheses: list[str] = field(default_factory=list)
    patterns: list[re.Pattern] = field(default_factory=list)


class Router:
    def __init__(self, components: dict[str, Component], families: dict[str, dict], metric_components: dict[str, str]):
        self.components, self.metric_components = components, metric_components
        self.families = {name: int(f.get("priority", 0)) for name, f in families.items()}
        self.merge_families = {name for name, f in families.items() if f.get("merge")}
        self._cache: dict[tuple[str, str], Component] = {}

    @classmethod
    def load(cls, path: Path | None = None) -> Router:
        raw = yaml.safe_load(Path(path or DEFAULT_ROUTING).read_text())
        components = {
            name: Component(name=name, title=c["title"], role=c["role"], family=c["family"], kind=c["kind"],
                            hypotheses=list(c.get("hypotheses", [])),
                            patterns=[re.compile(p, re.IGNORECASE) for p in c.get("patterns", [])])
            for name, c in raw["components"].items()}
        return cls(components, dict(raw["families"]), dict(raw["metric_components"]))

    def get(self, name: str) -> Component:
        return self.components[name]

    def priority(self, family: str) -> int:
        return self.families.get(family, 0)

    def same_problem(self, component_a: str, component_b: str) -> bool:
        """Signals of these two components belong to one incident."""
        a, b = self.components[component_a], self.components[component_b]
        return a.name == b.name or (a.family == b.family and a.family in self.merge_families)

    def component_of(self, signal: Signal) -> Component:
        cache_key = (signal.kind, signal.label)
        if cache_key not in self._cache:
            self._cache[cache_key] = self._resolve(signal)
        return self._cache[cache_key]

    def _resolve(self, signal: Signal) -> Component:
        if signal.kind != "log_burst":
            return self.components[self.metric_components[signal.kind]]
        for component in self.components.values():
            if any(p.search(signal.label) for p in component.patterns):
                return component
        return self.components[FALLBACK_COMPONENT]
