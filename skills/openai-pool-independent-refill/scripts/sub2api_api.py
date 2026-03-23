from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Optional

from curl_cffi import requests as cffi_requests


DEFAULT_TIMEOUT = 15


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        parts = str(token or "").split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        pad = 4 - len(payload) % 4
        if pad != 4:
            payload += "=" * pad
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def build_account_payload(email: str, token_data: Dict[str, Any]) -> Dict[str, Any]:
    access_token = token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    id_token = token_data.get("id_token", "")

    at_payload = decode_jwt_payload(access_token) if access_token else {}
    at_auth = at_payload.get("https://api.openai.com/auth") or {}
    chatgpt_account_id = at_auth.get("chatgpt_account_id", "") or token_data.get("account_id", "")
    chatgpt_user_id = at_auth.get("chatgpt_user_id", "")
    exp_timestamp = at_payload.get("exp", 0)
    expires_at = exp_timestamp if isinstance(exp_timestamp, int) and exp_timestamp > 0 else int(time.time()) + 863999

    it_payload = decode_jwt_payload(id_token) if id_token else {}
    it_auth = it_payload.get("https://api.openai.com/auth") or {}
    organization_id = it_auth.get("organization_id", "")
    if not organization_id:
        orgs = it_auth.get("organizations") or []
        if orgs:
            organization_id = (orgs[0] or {}).get("id", "")

    return {
        "name": email,
        "notes": "",
        "platform": "openai",
        "type": "oauth",
        "credentials": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 863999,
            "expires_at": expires_at,
            "chatgpt_account_id": chatgpt_account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "organization_id": organization_id,
        },
        "extra": {"email": email},
        "proxy_id": None,
        "concurrency": 10,
        "priority": 1,
        "rate_multiplier": 1,
        "group_ids": [2, 4],
        "expires_at": None,
        "auto_pause_on_expired": True,
    }


def extract_page_payload(body: Any) -> Dict[str, Any]:
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict):
            return data
        return body
    return {}


def item_matches_identity(item: Dict[str, Any], email: str, refresh_token: str) -> bool:
    email_norm = str(email or "").strip().lower()
    refresh_token_norm = str(refresh_token or "").strip()
    name = str(item.get("name") or "").strip().lower()
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    credentials = item.get("credentials") if isinstance(item.get("credentials"), dict) else {}
    item_email = str(extra.get("email") or "").strip().lower()
    item_refresh_token = str(credentials.get("refresh_token") or "").strip()
    if refresh_token_norm and item_refresh_token and item_refresh_token == refresh_token_norm:
        return True
    if email_norm and (name == email_norm or item_email == email_norm):
        return True
    return False


def _headers(bearer: str, base_url: str | None = None) -> Dict[str, str]:
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json, text/plain, */*",
    }
    if base_url:
        headers["Content-Type"] = "application/json"
        headers["Referer"] = base_url.rstrip("/") + "/admin/accounts"
    return headers


def create_account(base_url: str, bearer: str, email: str, token_data: Dict[str, Any]) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/v1/admin/accounts"
    payload = build_account_payload(email, token_data)
    try:
        resp = cffi_requests.post(
            url,
            json=payload,
            headers=_headers(bearer, base_url),
            impersonate="chrome",
            timeout=20,
        )
        return {"ok": resp.status_code in (200, 201), "status": resp.status_code, "body": resp.text[:300]}
    except Exception as exc:
        return {"ok": False, "status": 0, "body": str(exc)}


def update_account(base_url: str, bearer: str, account_id: int, email: str, token_data: Dict[str, Any]) -> Dict[str, Any]:
    url = base_url.rstrip("/") + f"/api/v1/admin/accounts/{int(account_id)}"
    create_payload = build_account_payload(email, token_data)
    credentials = create_payload.get("credentials") if isinstance(create_payload.get("credentials"), dict) else {}
    extra = create_payload.get("extra") if isinstance(create_payload.get("extra"), dict) else {}
    payload = {
        "name": str(email or "").strip(),
        "credentials": credentials,
        "extra": extra,
        "concurrency": create_payload.get("concurrency", 10),
        "priority": create_payload.get("priority", 1),
        "status": "active",
        "auto_pause_on_expired": True,
    }
    try:
        resp = cffi_requests.put(
            url,
            json=payload,
            headers=_headers(bearer, base_url),
            impersonate="chrome",
            timeout=20,
        )
        return {"ok": resp.status_code in (200, 201), "status": resp.status_code, "body": resp.text[:300]}
    except Exception as exc:
        return {"ok": False, "status": 0, "body": str(exc)}


def list_accounts_page(base_url: str, bearer: str, page: int = 1, page_size: int = 100, timeout: int = DEFAULT_TIMEOUT, search: str = "") -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "page": page,
        "page_size": page_size,
        "platform": "openai",
        "type": "oauth",
    }
    if str(search or "").strip():
        params["search"] = str(search).strip().lower()
    resp = cffi_requests.get(
        base_url.rstrip("/") + "/api/v1/admin/accounts",
        params=params,
        headers=_headers(bearer),
        impersonate="chrome",
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    return extract_page_payload(body)


def list_all_accounts(base_url: str, bearer: str, timeout: int = DEFAULT_TIMEOUT, page_size: int = 100) -> List[Dict[str, Any]]:
    all_accounts: List[Dict[str, Any]] = []
    page = 1
    while True:
        data = list_accounts_page(base_url, bearer, page=page, page_size=page_size, timeout=timeout)
        items = data.get("items") or []
        if not isinstance(items, list):
            items = []
        all_accounts.extend([item for item in items if isinstance(item, dict)])
        if not items or len(items) < page_size:
            break
        total = data.get("total")
        if isinstance(total, int) and total > 0 and len(all_accounts) >= total:
            break
        page += 1
    return all_accounts


def get_dashboard_stats(base_url: str, bearer: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    resp = cffi_requests.get(
        base_url.rstrip("/") + "/api/v1/admin/dashboard/stats",
        params={"timezone": "Asia/Shanghai"},
        headers=_headers(bearer),
        impersonate="chrome",
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("data") if isinstance(data.get("data"), dict) else data


def find_existing_account(base_url: str, bearer: str, email: str, refresh_token: str, max_pages: int = 8) -> Optional[Dict[str, Any]]:
    email_norm = str(email or "").strip().lower()
    refresh_token_norm = str(refresh_token or "").strip()
    if not email_norm and not refresh_token_norm:
        return None

    page_size = 100
    page = 1
    scanned_without_search = 0
    while page <= max_pages:
        try:
            data = list_accounts_page(base_url, bearer, page=page, page_size=page_size, timeout=DEFAULT_TIMEOUT, search=email_norm)
        except Exception:
            return None
        items = data.get("items") if isinstance(data.get("items"), list) else []
        for item in items:
            if isinstance(item, dict) and item_matches_identity(item, email_norm, refresh_token_norm):
                return item
        total_raw = data.get("total")
        try:
            total = int(total_raw) if total_raw is not None else 0
        except (TypeError, ValueError):
            total = 0
        if len(items) < page_size or (total > 0 and page * page_size >= total):
            break
        page += 1

    if refresh_token_norm:
        page = 1
        while page <= 3:
            try:
                data = list_accounts_page(base_url, bearer, page=page, page_size=page_size, timeout=DEFAULT_TIMEOUT)
            except Exception:
                return None
            items = data.get("items") if isinstance(data.get("items"), list) else []
            for item in items:
                if isinstance(item, dict) and item_matches_identity(item, "", refresh_token_norm):
                    return item
            scanned_without_search += len(items)
            if len(items) < page_size or scanned_without_search >= 300:
                break
            page += 1
    return None


def push_account_with_dedupe(base_url: str, bearer: str, email: str, token_data: Dict[str, Any], check_before: bool = True, check_after: bool = True) -> Dict[str, Any]:
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    existing: Optional[Dict[str, Any]] = None
    if check_before:
        existing = find_existing_account(base_url, bearer, email, refresh_token)
        if existing is not None:
            existing_id = existing.get("id")
            try:
                existing_int = int(existing_id)
            except (TypeError, ValueError):
                existing_int = None
            if existing_int is not None and existing_int > 0:
                update_result = update_account(base_url, bearer, existing_int, email, token_data)
                if update_result.get("ok"):
                    return {
                        "ok": True,
                        "status": int(update_result.get("status") or 200),
                        "body": "existing account updated",
                        "skipped": False,
                        "reason": "updated_existing_before_create",
                        "existing_id": existing_int,
                    }
                return {
                    "ok": False,
                    "status": int(update_result.get("status") or 0),
                    "body": "existing account update failed",
                    "skipped": False,
                    "reason": "exists_before_create_update_failed",
                    "existing_id": existing_int,
                    "update_status": int(update_result.get("status") or 0),
                    "update_body": str(update_result.get("body") or "")[:240],
                }
            return {
                "ok": True,
                "status": 200,
                "body": "account already exists",
                "skipped": True,
                "reason": "exists_before_create",
                "existing_id": existing_id,
            }

    result = create_account(base_url, bearer, email, token_data)
    if result.get("ok"):
        result["skipped"] = False
        result["reason"] = "created"
        return result

    if check_after:
        existing = find_existing_account(base_url, bearer, email, refresh_token)
        if existing is not None:
            return {
                "ok": True,
                "status": int(result.get("status") or 200),
                "body": "request failed but account exists",
                "skipped": True,
                "reason": "exists_after_create",
                "existing_id": existing.get("id"),
            }

    result.setdefault("skipped", False)
    result.setdefault("reason", "create_failed")
    return result


def is_abnormal_status(status: Any) -> bool:
    return str(status or "").strip().lower() in ("error", "disabled")


def normalize_account_id(raw: Any) -> Optional[int]:
    try:
        account_id = int(raw)
    except (TypeError, ValueError):
        return None
    if account_id <= 0:
        return None
    return account_id


def account_identity(item: Dict[str, Any]) -> Dict[str, str]:
    email = ""
    refresh_token = ""
    extra = item.get("extra")
    if isinstance(extra, dict):
        email = str(extra.get("email") or "").strip().lower()
    if not email:
        name = str(item.get("name") or "").strip().lower()
        if "@" in name:
            email = name
    credentials = item.get("credentials")
    if isinstance(credentials, dict):
        refresh_token = str(credentials.get("refresh_token") or "").strip()
    return {"email": email, "refresh_token": refresh_token}


def account_sort_key(item: Dict[str, Any]) -> tuple[str, int]:
    updated = str(item.get("updated_at") or item.get("updatedAt") or "")
    try:
        item_id = int(item.get("id") or 0)
    except (TypeError, ValueError):
        item_id = 0
    return (updated, item_id)


def build_dedupe_plan(all_accounts: List[Dict[str, Any]], details_limit: int = 120) -> Dict[str, Any]:
    id_to_account: Dict[int, Dict[str, Any]] = {}
    parent: Dict[int, int] = {}
    key_to_ids: Dict[str, List[int]] = {}
    for item in all_accounts:
        account_id = normalize_account_id(item.get("id"))
        if account_id is None:
            continue
        id_to_account[account_id] = item
        parent[account_id] = account_id
        identity = account_identity(item)
        if identity["email"]:
            key_to_ids.setdefault(f"email:{identity['email']}", []).append(account_id)
        if identity["refresh_token"]:
            key_to_ids.setdefault(f"rt:{identity['refresh_token']}", []).append(account_id)

    def find(x: int) -> int:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != x:
            nxt = parent[x]
            parent[x] = root
            x = nxt
        return root

    def union(a: int, b: int) -> None:
        ra = find(a)
        rb = find(b)
        if ra != rb:
            parent[rb] = ra

    for ids in key_to_ids.values():
        if len(ids) > 1:
            head = ids[0]
            for account_id in ids[1:]:
                union(head, account_id)

    components: Dict[int, List[int]] = {}
    for account_id in id_to_account.keys():
        root = find(account_id)
        components.setdefault(root, []).append(account_id)

    duplicate_groups = [ids for ids in components.values() if len(ids) > 1]
    delete_ids: List[int] = []
    groups_preview: List[Dict[str, Any]] = []
    for group_ids in duplicate_groups:
        group_items = [id_to_account[item_id] for item_id in group_ids]
        keep_item = max(group_items, key=account_sort_key)
        keep_id = normalize_account_id(keep_item.get("id")) or 0
        group_delete_ids = sorted([item_id for item_id in group_ids if item_id != keep_id], reverse=True)
        delete_ids.extend(group_delete_ids)
        if len(groups_preview) < details_limit:
            emails = sorted({account_identity(item)["email"] for item in group_items if account_identity(item)["email"]})
            groups_preview.append({
                "keep_id": keep_id,
                "delete_ids": group_delete_ids,
                "size": len(group_ids),
                "emails": emails,
            })
    return {
        "duplicate_groups": len(duplicate_groups),
        "duplicate_accounts": sum(len(group) for group in duplicate_groups),
        "delete_ids": delete_ids,
        "groups_preview": groups_preview,
        "truncated_groups": max(0, len(duplicate_groups) - len(groups_preview)),
    }


def delete_account(base_url: str, bearer: str, account_id: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
    try:
        resp = cffi_requests.delete(
            base_url.rstrip("/") + f"/api/v1/admin/accounts/{account_id}",
            headers=_headers(bearer),
            impersonate="chrome",
            timeout=timeout,
        )
        return resp.status_code in (200, 204)
    except Exception:
        return False


def refresh_account(base_url: str, bearer: str, account_id: int, timeout: int = 30) -> bool:
    try:
        resp = cffi_requests.post(
            base_url.rstrip("/") + f"/api/v1/admin/accounts/{account_id}/refresh",
            headers=_headers(bearer),
            impersonate="chrome",
            timeout=timeout,
        )
        return resp.status_code in (200, 201)
    except Exception:
        return False


def list_account_status_by_ids(base_url: str, bearer: str, ids: List[int], timeout: int = DEFAULT_TIMEOUT) -> Dict[int, str]:
    result: Dict[int, str] = {}
    id_set = {account_id for account_id in ids if isinstance(account_id, int) and account_id > 0}
    page = 1
    while id_set:
        data = list_accounts_page(base_url, bearer, page=page, page_size=100, timeout=timeout)
        items = data.get("items") or []
        if not items:
            break
        for item in items:
            aid = item.get("id")
            if aid in id_set:
                result[int(aid)] = str(item.get("status") or "")
                id_set.discard(aid)
        total = data.get("total", 0)
        if page * 100 >= total or len(items) < 100:
            break
        page += 1
    return result
