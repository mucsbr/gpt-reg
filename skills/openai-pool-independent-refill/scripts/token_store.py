from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class TokenStore:
    def __init__(self, token_dir: Path):
        self.token_dir = token_dir

    def ensure_dir(self) -> None:
        self.token_dir.mkdir(parents=True, exist_ok=True)

    def list_tokens(self) -> List[Path]:
        if not self.token_dir.exists():
            return []
        return sorted(self.token_dir.glob("*.json"))

    def save_token(self, file_name: str, token_data: Dict[str, Any]) -> Path:
        self.ensure_dir()
        path = self.token_dir / file_name
        path.write_text(json.dumps(token_data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
