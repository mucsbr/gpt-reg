from __future__ import annotations

from typing import Any, Dict

from cpa_client import CpaClient
from sub2api_api import push_account_with_dedupe


class UploadResult(dict):
    pass


def upload_to_cpa(client: CpaClient, token_data: Dict[str, Any], file_name: str, proxy: str = "") -> UploadResult:
    ok = client.upload_token(file_name, token_data, proxy=proxy)
    return UploadResult({
        "ok": ok,
        "platform": "cpa",
        "status": 200 if ok else 500,
        "reason": "uploaded" if ok else "upload_failed",
    })


def upload_to_sub2api(config: Dict[str, Any], token_data: Dict[str, Any], email: str) -> UploadResult:
    sub2api_cfg = config.get("sub2api") or {}
    base_url = str(sub2api_cfg.get("base_url") or "").strip()
    bearer = str(sub2api_cfg.get("bearer_token") or "").strip()
    if not base_url or not bearer:
        return UploadResult({
            "ok": False,
            "platform": "sub2api",
            "status": 0,
            "reason": "missing_config",
            "body": "missing base_url or bearer_token",
        })
    result = push_account_with_dedupe(
        base_url=base_url,
        bearer=bearer,
        email=email,
        token_data=token_data,
        check_before=True,
        check_after=True,
    )
    payload = {
        "platform": "sub2api",
        "ok": bool(result.get("ok")),
        "status": int(result.get("status") or 0),
        "reason": str(result.get("reason") or ("uploaded" if result.get("ok") else "upload_failed")),
        "skipped": bool(result.get("skipped", False)),
        "existing_id": result.get("existing_id"),
        "body": str(result.get("body") or "")[:240],
    }
    if "update_status" in result:
        payload["update_status"] = int(result.get("update_status") or 0)
    if "update_body" in result:
        payload["update_body"] = str(result.get("update_body") or "")[:240]
    return UploadResult(payload)
