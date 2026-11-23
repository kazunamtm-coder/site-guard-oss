from __future__ import annotations

import json
import re
from pathlib import Path

from .config import ROOT

STATE_DIR = ROOT / "data" / "state"


def _path(site_name: str) -> Path:
    return STATE_DIR / (re.sub(r"[^A-Za-z0-9_-]", "_", site_name) + ".json")


def load(site_name: str) -> dict:
    p = _path(site_name)
    return json.loads(p.read_text()) if p.exists() else {}


def save(site_name: str, state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    p = _path(site_name)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
    tmp.replace(p)
