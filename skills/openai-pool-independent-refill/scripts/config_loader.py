from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG_NAME = "config.json"


def load_config(config_path: str) -> Dict[str, Any]:
    path = Path(config_path).expanduser().resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def resolve_token_dir(config: Dict[str, Any], config_path: str) -> Path:
    base = Path(config_path).expanduser().resolve().parent
    token_dir = str(((config.get("token_store") or {}).get("dir") or "./tokens")).strip() or "./tokens"
    path = Path(token_dir)
    if not path.is_absolute():
        path = (base / path).resolve()
    return path
