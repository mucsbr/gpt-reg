from __future__ import annotations

import asyncio
from typing import Any, Dict

from openai_pool_orchestrator.pool_maintainer import PoolMaintainer


class CpaClient:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = bool(config.get("enabled", False))
        self.maintainer = PoolMaintainer(
            cpa_base_url=str(config.get("base_url") or "").strip(),
            cpa_token=str(config.get("token") or "").strip(),
            target_type=str(config.get("target_type") or "codex").strip() or "codex",
            min_candidates=int(config.get("min_candidates") or 800),
            used_percent_threshold=int(config.get("used_percent_threshold") or 95),
        )

    def get_status(self) -> Dict[str, Any]:
        return self.maintainer.get_pool_status()

    def calculate_gap(self) -> int:
        return self.maintainer.calculate_gap()

    def classify_accounts(self, workers: int = 20, timeout: int = 10, retries: int = 1) -> Dict[str, Any]:
        result = asyncio.run(self.maintainer.probe_accounts_async(workers=workers, timeout=timeout, retries=retries))
        invalid = list(result.get("invalid") or [])
        return {
            "available": max(0, int(result.get("candidates", 0)) - len(invalid)),
            "invalid_401": [item for item in invalid if item.get("invalid_401")],
            "invalid_used_percent": [item for item in invalid if item.get("invalid_used_percent")],
            "errors": [item for item in invalid if item.get("error")],
            "raw": result,
        }

    def upload_token(self, filename: str, token_data: Dict[str, Any], proxy: str = "") -> bool:
        return self.maintainer.upload_token(filename, token_data, proxy=proxy)
