from __future__ import annotations

from typing import Any, Dict


def compute_platform_gaps(config: Dict[str, Any], cpa_status: Dict[str, Any] | None, sub2api_status: Dict[str, Any] | None) -> Dict[str, int]:
    cpa_gap = 0
    sub2api_gap = 0

    cpa_cfg = config.get("cpa") or {}
    if cpa_cfg.get("enabled"):
        threshold = int(cpa_cfg.get("min_candidates") or 800)
        current = int((cpa_status or {}).get("candidates") or 0)
        cpa_gap = max(0, threshold - current)

    sub2api_cfg = config.get("sub2api") or {}
    if sub2api_cfg.get("enabled") and bool(sub2api_cfg.get("auto_sync", True)):
        threshold = int(sub2api_cfg.get("min_candidates") or 200)
        current = int((sub2api_status or {}).get("candidates") or 0)
        sub2api_gap = max(0, threshold - current)

    return {"cpa_gap": cpa_gap, "sub2api_gap": sub2api_gap}


def compute_total_gap(upload_mode: str, cpa_gap: int, sub2api_gap: int) -> int:
    mode = str(upload_mode or "snapshot").strip().lower() or "snapshot"
    if mode not in {"snapshot", "decoupled"}:
        mode = "snapshot"
    return cpa_gap + sub2api_gap if mode == "snapshot" else max(cpa_gap, sub2api_gap)


def should_refill(config: Dict[str, Any], gaps: Dict[str, int]) -> Dict[str, Any]:
    blockers = []
    if not bool(config.get("auto_register", False)):
        blockers.append("auto_register 未开启")
    proxy = str(config.get("proxy") or "").strip()
    proxy_pool_enabled = bool(((config.get("proxy_pool") or {}).get("enabled")))
    if not proxy and not proxy_pool_enabled:
        blockers.append("未配置固定代理且代理池未启用")
    total_gap = compute_total_gap(str(config.get("upload_mode") or "snapshot"), gaps["cpa_gap"], gaps["sub2api_gap"])
    if total_gap <= 0:
        blockers.append("gap 计算结果为 0")
    return {"ok": not blockers, "blockers": blockers, "total_gap": total_gap}


def build_refill_plan(config: Dict[str, Any], cpa_status: Dict[str, Any] | None, sub2api_status: Dict[str, Any] | None) -> Dict[str, Any]:
    gaps = compute_platform_gaps(config, cpa_status, sub2api_status)
    decision = should_refill(config, gaps)
    return {
        "upload_mode": str(config.get("upload_mode") or "snapshot"),
        "cpa_status": cpa_status,
        "sub2api_status": sub2api_status,
        **gaps,
        **decision,
    }
