"""Settings: config/argus.yaml, overridable by ARGUS_* environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "argus.yaml"


class Paths(BaseModel):
    data_dir: Path = Path("../data")
    var_dir: Path = Path("var")
    out_dir: Path = Path(".")
    routing: Path = Path("config/routing.yaml")
    gold: Path = Path("evals/gold.yaml")

    @property
    def db(self) -> Path:
        return self.var_dir / "argus.duckdb"


class Config(BaseModel):
    paths: Paths = Field(default_factory=Paths)
    detect: dict[str, Any] = Field(default_factory=dict)
    incidents: dict[str, Any] = Field(default_factory=dict)
    llm: dict[str, Any] = Field(default_factory=dict)
    dedup: dict[str, Any] = Field(default_factory=dict)
    predict: dict[str, Any] = Field(default_factory=dict)
    slack: dict[str, Any] = Field(default_factory=dict)


ENV_PATHS = {"ARGUS_DATA_DIR": "data_dir", "ARGUS_VAR_DIR": "var_dir", "ARGUS_OUT_DIR": "out_dir"}


def load_config(path: Path | None = None, **path_overrides: Path | None) -> Config:
    path = Path(path) if path else DEFAULT_CONFIG
    raw = yaml.safe_load(path.read_text()) if path.exists() else {}
    cfg = Config.model_validate(raw or {})
    base = path.resolve().parent.parent if path.exists() else REPO_ROOT
    for env, field in ENV_PATHS.items():
        if os.environ.get(env):
            setattr(cfg.paths, field, Path(os.environ[env]))
    for field, value in path_overrides.items():
        if value is not None:
            setattr(cfg.paths, field, Path(value))
    for field in Paths.model_fields:
        value = getattr(cfg.paths, field)
        if not value.is_absolute():
            setattr(cfg.paths, field, (base / value).resolve())
    if os.environ.get("ARGUS_LLM"):
        cfg.llm["mode"] = os.environ["ARGUS_LLM"]
    return cfg
