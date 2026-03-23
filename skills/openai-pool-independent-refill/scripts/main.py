from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from config_loader import load_config, resolve_token_dir
from cpa_client import CpaClient
from refill_planner import build_refill_plan
from register_runner import RegistrationNotReadyError, run_registration
from sub2api_client import Sub2ApiClient
from token_store import TokenStore
from uploader import upload_to_cpa, upload_to_sub2api


BRIDGE_DEPENDENCIES = {
    "registration": {
        "enabled": False,
        "source": "skills.openai-pool-independent-refill.scripts.register_engine",
        "reason": "注册入口已迁入 skill 内部，但主流程仍待继续补全",
    },
    "cpa_client": {
        "enabled": True,
        "source": "openai_pool_orchestrator.pool_maintainer.PoolMaintainer",
        "reason": "CPA client 当前仍包装主包 maintainer",
    },
    "sub2api_client": {
        "enabled": False,
        "source": "skills.openai-pool-independent-refill.scripts.sub2api_api",
        "reason": "Sub2Api client 已迁入 skill 内部",
    },
    "sub2api_upload": {
        "enabled": False,
        "source": "skills.openai-pool-independent-refill.scripts.sub2api_api.push_account_with_dedupe",
        "reason": "Sub2Api 上传去重已迁入 skill 内部",
    },
}


def _bridge_status() -> Dict[str, Any]:
    return {
        "bridge_mode": any(item.get("enabled") for item in BRIDGE_DEPENDENCIES.values()),
        "bridge_dependencies": BRIDGE_DEPENDENCIES,
        "target_state": "no_bridge",
    }


def _build_clients(config: Dict[str, Any]) -> tuple[CpaClient | None, Sub2ApiClient | None]:
    cpa_cfg = config.get("cpa") or {}
    sub2api_cfg = config.get("sub2api") or {}
    cpa_client = CpaClient(cpa_cfg) if cpa_cfg.get("enabled") else None
    sub2api_client = Sub2ApiClient(sub2api_cfg) if sub2api_cfg.get("enabled") else None
    return cpa_client, sub2api_client


def _collect_status(config: Dict[str, Any]) -> Dict[str, Any]:
    cpa_client, sub2api_client = _build_clients(config)
    cpa_status = cpa_client.get_status() if cpa_client else None
    sub2api_status = sub2api_client.get_status() if sub2api_client else None
    return {
        "cpa": cpa_status,
        "sub2api": sub2api_status,
        "plan": build_refill_plan(config, cpa_status, sub2api_status),
        **_bridge_status(),
    }


def _summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {
        "requested": len(results),
        "registration_ok": 0,
        "registration_fail": 0,
        "cpa_ok": 0,
        "cpa_fail": 0,
        "sub2api_ok": 0,
        "sub2api_fail": 0,
        "sub2api_skipped": 0,
    }
    for item in results:
        if item.get("registration", {}).get("ok"):
            summary["registration_ok"] += 1
        else:
            summary["registration_fail"] += 1

        cpa_result = item.get("uploads", {}).get("cpa")
        if isinstance(cpa_result, dict):
            if cpa_result.get("ok"):
                summary["cpa_ok"] += 1
            else:
                summary["cpa_fail"] += 1

        sub2api_result = item.get("uploads", {}).get("sub2api")
        if isinstance(sub2api_result, dict):
            if sub2api_result.get("skipped"):
                summary["sub2api_skipped"] += 1
            elif sub2api_result.get("ok"):
                summary["sub2api_ok"] += 1
            else:
                summary["sub2api_fail"] += 1
    return summary


def _build_debridge_plan() -> List[Dict[str, Any]]:
    return [
        {
            "phase": 1,
            "goal": "迁出 Sub2Api 上传去重逻辑",
            "remove_bridge": "openai_pool_orchestrator.server._push_account_api_with_dedupe",
        },
        {
            "phase": 2,
            "goal": "迁出注册执行层与 mail provider 路由",
            "remove_bridge": "openai_pool_orchestrator.register.run",
        },
        {
            "phase": 3,
            "goal": "迁出 CPA/Sub2Api maintainer 包装依赖",
            "remove_bridge": "openai_pool_orchestrator.pool_maintainer",
        },
    ]


def cmd_status(config: Dict[str, Any]) -> Dict[str, Any]:
    return _collect_status(config)


def cmd_plan(config: Dict[str, Any]) -> Dict[str, Any]:
    payload = _collect_status(config)
    return {
        "plan": payload["plan"],
        "bridge_mode": payload["bridge_mode"],
        "bridge_dependencies": payload["bridge_dependencies"],
        "debridge_plan": _build_debridge_plan(),
        "target_state": payload["target_state"],
    }


def cmd_refill(config: Dict[str, Any], config_path: str) -> Dict[str, Any]:
    snapshot = _collect_status(config)
    plan = snapshot["plan"]
    if not plan.get("ok"):
        return {
            "status": "blocked",
            "plan": plan,
            "summary": {"requested": 0},
            "bridge_mode": snapshot["bridge_mode"],
            "bridge_dependencies": snapshot["bridge_dependencies"],
            "target_state": snapshot["target_state"],
        }

    target_count = int(((config.get("register") or {}).get("target_count") or plan.get("total_gap") or 1))
    token_dir = resolve_token_dir(config, config_path)
    store = TokenStore(token_dir)
    cpa_client, _ = _build_clients(config)

    try:
        registration_results = run_registration(config, target_count=target_count)
    except RegistrationNotReadyError as exc:
        return {
            "status": "not_ready",
            "plan": plan,
            "error": str(exc),
            "summary": {"requested": target_count},
            "bridge_mode": snapshot["bridge_mode"],
            "bridge_dependencies": snapshot["bridge_dependencies"],
            "target_state": snapshot["target_state"],
        }

    results = []
    for item in registration_results:
        attempt_payload: Dict[str, Any] = {
            "attempt": item.get("attempt"),
            "registration": {
                "ok": bool(item.get("ok")),
                "reason": item.get("reason"),
                "email": item.get("email"),
                "has_refresh_token": bool(item.get("has_refresh_token", False)),
            },
            "uploads": {},
        }
        if not item.get("ok") or not item.get("token_data"):
            results.append(attempt_payload)
            continue

        token_data = item["token_data"]
        email = str(item.get("email") or token_data.get("email") or "unknown").strip() or "unknown"
        file_name = f"token_{email.replace('@', '_')}_{time.time_ns()}.json"
        saved_path = store.save_token(file_name, token_data)
        attempt_payload["saved_file"] = str(saved_path)

        if cpa_client:
            attempt_payload["uploads"]["cpa"] = upload_to_cpa(
                cpa_client,
                token_data,
                file_name,
                proxy=str(config.get("proxy") or ""),
            )

        if bool(((config.get("sub2api") or {}).get("auto_sync", True))):
            attempt_payload["uploads"]["sub2api"] = upload_to_sub2api(config, token_data, email)

        results.append(attempt_payload)

    summary = _summarize_results(results)
    overall_ok = summary["registration_ok"] > 0 and summary["registration_fail"] == 0
    return {
        "status": "ok" if overall_ok else "partial",
        "plan": plan,
        "summary": summary,
        "results": results,
        "bridge_mode": snapshot["bridge_mode"],
        "bridge_dependencies": snapshot["bridge_dependencies"],
        "target_state": snapshot["target_state"],
        "debridge_plan": _build_debridge_plan(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent refill skill CLI")
    parser.add_argument("command", choices=["status", "plan", "refill"])
    parser.add_argument("--config", required=True, help="Path to skill config JSON")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.command == "status":
        payload = cmd_status(config)
    elif args.command == "plan":
        payload = cmd_plan(config)
    else:
        payload = cmd_refill(config, args.config)

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
