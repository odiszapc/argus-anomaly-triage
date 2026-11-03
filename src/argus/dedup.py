"""Before a task is created: is there already one for this problem?

A new incident repeats an earlier task when it is the same problem (component, or a merge family
such as cache + DB), its cause templates overlap (Jaccard) or read alike (embeddings), and the task
was active within the window. A cause template never seen before means a new failure mode, so it
gets its own task even if the component matches (a Valkey LOADING storm is not "more Redis errors").
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta

import httpx
import numpy as np

from .correlate import Incident
from .routing import Router


def text_vector(text: str, dim: int = 512) -> np.ndarray:
    """Hashed character trigrams, L2-normalised: the offline stand-in for embeddings."""
    v = np.zeros(dim)
    for word in text.lower().split():
        w = f" {word} "
        for i in range(len(w) - 2):
            v[int(hashlib.md5(w[i:i + 3].encode()).hexdigest()[:8], 16) % dim] += 1.0
    n = np.linalg.norm(v)
    return v / n if n else v


class Embedder:
    def __init__(self, host: str | None, model: str, enabled: bool = True):
        self.host = host if not host or host.startswith("http") else f"http://{host}"
        self.model, self.enabled = model, enabled and bool(host)
        self.cache: dict[str, np.ndarray] = {}

    def __call__(self, text: str) -> np.ndarray:
        if text not in self.cache:
            self.cache[text] = self._embed(text)
        return self.cache[text]

    def _embed(self, text: str) -> np.ndarray:
        if self.enabled:
            try:
                r = httpx.post(f"{self.host}/api/embed", json={"model": self.model, "input": text}, timeout=30.0)
                r.raise_for_status()
                v = np.asarray(r.json()["embeddings"][0], dtype=float)
                return v / (np.linalg.norm(v) or 1.0)
            except (httpx.HTTPError, KeyError, IndexError, ValueError):
                self.enabled = False  # one failure switches to the offline vectors for the rest of the run
        return text_vector(text)


class Dedup:
    def __init__(self, cfg: dict, router: Router):
        self.router = router
        self.window = timedelta(hours=float(cfg.get("window_h", 72)))
        self.jaccard_min = float(cfg.get("jaccard", 0.34))
        self.cosine_min = float(cfg.get("cosine", 0.85))
        self.embed = Embedder(os.environ.get("OLLAMA_HOST") or cfg.get("ollama_host"),
                              cfg.get("embedding_model", "qwen3-embedding:0.6b"), bool(cfg.get("embeddings", True)))
        self.last_reason = ""

    def causes(self, incident: Incident) -> dict[str, str]:
        """key → label of the signals that describe the problem itself (not its symptoms)."""
        own = {s.key: s.label for s in incident.log_signals()
               if self.router.same_problem(self.router.component_of(s).name, incident.component)}
        if own:
            return own
        metric = {f"{s.kind}:{s.key}:{s.attrs.get('direction', '')}": s.label for s in incident.signals.values()
                  if s.kind != "log_burst"}
        return metric or {s.key: s.label for s in incident.log_signals()}

    @staticmethod
    def _volume(incident: Incident, key: str) -> float:
        return sum(s.total for s in incident.signals.values() if s.key == key)

    def match(self, incident: Incident, triage, memory, now: datetime):
        mine = self.causes(incident)
        new = {s.key for s in incident.log_signals() if s.attrs.get("new_template") and s.key in mine}
        by_uid = {i.uid: i for i in memory.incidents}
        for record in sorted(memory.tasks.values(), key=lambda r: r.last_active or r.opened_at, reverse=True):
            if now - (record.last_active or record.opened_at) > self.window:
                continue
            parent = by_uid.get(record.incident_uid)
            if parent is None or not self.router.same_problem(parent.component, incident.component):
                continue
            theirs: dict[str, str] = dict(self.causes(parent))
            for r in record.repeats:
                if r["uid"] in by_uid:
                    theirs.update(self.causes(by_uid[r["uid"]]))
            if new - set(theirs):
                continue
            a, b = set(mine), set(theirs)
            jaccard = len(a & b) / len(a | b) if a | b else 1.0
            dominant = max(mine, key=lambda k: self._volume(incident, k), default=None)
            if dominant in b:
                self.last_reason = f"главная сигнатура уже была в задаче («{mine[dominant][:60]}»)"
                return record
            if jaccard >= self.jaccard_min:
                self.last_reason = f"те же сигнатуры (Jaccard {jaccard:.2f})"
                return record
            cosine = float(self.embed(" | ".join(sorted(mine.values()))) @ self.embed(" | ".join(sorted(theirs.values()))))
            if cosine >= self.cosine_min:
                self.last_reason = f"похожие сигнатуры (косинус {cosine:.2f})"
                return record
        return None
