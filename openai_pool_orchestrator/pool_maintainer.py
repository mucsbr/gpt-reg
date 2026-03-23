"""
账号池维护模块
支持 CPA 平台和 Sub2Api 平台的探测、清理、计数和补号
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests as _requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import aiohttp
except ImportError:
    aiohttp = None

logger = logging.getLogger(__name__)

DEFAULT_MGMT_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"


def _mgmt_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _build_session(proxy: str = "") -> _requests.Session:
    s = _requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _get_item_type(item: Dict[str, Any]) -> str:
    return str(item.get("type") or item.get("typo") or "")


def _safe_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        return {}


def _extract_account_id(item: Dict[str, Any]) -> Optional[str]:
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return str(val)
    return None


def _parse_time_to_epoch(raw: Any) -> float:
    text = str(raw or "").strip()
    if not text:
        return 0.0
    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(iso_text).timestamp()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except Exception:
            continue
    return 0.0


class PoolMaintainer:
    def __init__(
        self,
        cpa_base_url: str,
        cpa_token: str,
        target_type: str = "codex",
        min_candidates: int = 800,
        used_percent_threshold: int = 95,
        user_agent: str = DEFAULT_MGMT_UA,
    ):
        self.base_url = cpa_base_url.rstrip("/")
        self.token = cpa_token
        self.target_type = target_type
        self.min_candidates = min_candidates
        self.used_percent_threshold = used_percent_threshold
        self.user_agent = user_agent

    def fetch_auth_files(self, timeout: int = 15) -> List[Dict[str, Any]]:
        resp = _requests.get(
            f"{self.base_url}/v0/management/auth-files",
            headers=_mgmt_headers(self.token),
            timeout=timeout,
        )
        resp.raise_for_status()
        raw = resp.json()
        data = raw if isinstance(raw, dict) else {}
        files = data.get("files", [])
        return files if isinstance(files, list) else []

    def get_pool_status(self, timeout: int = 15) -> Dict[str, Any]:
        try:
            files = self.fetch_auth_files(timeout)
            candidates = [f for f in files if _get_item_type(f).lower() == self.target_type.lower()]
            total = len(files)
            cand_count = len(candidates)
            return {
                "total": total,
                "candidates": cand_count,
                "error_count": max(0, total - cand_count),
                "threshold": self.min_candidates,
                "healthy": cand_count >= self.min_candidates,
                "percent": round(cand_count / self.min_candidates * 100, 1) if self.min_candidates > 0 else 100,
                "last_checked": time.strftime("%Y-%m-%d %H:%M:%S"),
                "error": None,
            }
        except Exception as e:
            return {
                "total": 0,
                "candidates": 0,
                "error_count": 0,
                "threshold": self.min_candidates,
                "healthy": False,
                "percent": 0,
                "last_checked": time.strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e),
            }

    def test_connection(self, timeout: int = 10) -> Dict[str, Any]:
        try:
            files = self.fetch_auth_files(timeout)
            candidates = [f for f in files if _get_item_type(f).lower() == self.target_type.lower()]
            return {
                "ok": True,
                "total": len(files),
                "candidates": len(candidates),
                "message": f"连接成功，共 {len(files)} 个账号，{len(candidates)} 个 {self.target_type} 账号",
            }
        except Exception as e:
            return {"ok": False, "total": 0, "candidates": 0, "message": f"连接失败: {e}"}

    async def probe_accounts_async(
        self, workers: int = 20, timeout: int = 10, retries: int = 1,
    ) -> Dict[str, Any]:
        if aiohttp is None:
            raise RuntimeError("需要安装 aiohttp: pip install aiohttp")

        files = self.fetch_auth_files(timeout)
        candidates = [f for f in files if _get_item_type(f).lower() == self.target_type.lower()]

        if not candidates:
            return {"total": len(files), "candidates": 0, "invalid": [], "files": files}

        semaphore = asyncio.Semaphore(max(1, workers))
        connector = aiohttp.TCPConnector(limit=max(1, workers))
        client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))

        async def probe_one(session: aiohttp.ClientSession, item: Dict[str, Any]) -> Dict[str, Any]:
            auth_index = item.get("auth_index")
            name = item.get("name") or item.get("id")
            result = {
                "name": name,
                "auth_index": auth_index,
                "invalid_401": False,
                "invalid_used_percent": False,
                "used_percent": None,
                "error": None,
            }
            if not auth_index:
                result["error"] = "missing auth_index"
                return result

            account_id = _extract_account_id(item)
            call_header = {
                "Authorization": "Bearer $TOKEN$",
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            }
            if account_id:
                call_header["Chatgpt-Account-Id"] = account_id

            payload = {
                "authIndex": auth_index,
                "method": "GET",
                "url": "https://chatgpt.com/backend-api/wham/usage",
                "header": call_header,
            }

            for attempt in range(retries + 1):
                try:
                    async with semaphore:
                        async with session.post(
                            f"{self.base_url}/v0/management/api-call",
                            headers={**_mgmt_headers(self.token), "Content-Type": "application/json"},
                            json=payload,
                            timeout=timeout,
                        ) as resp:
                            text = await resp.text()
                            if resp.status >= 400:
                                raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
                            data = _safe_json(text)
                            sc = data.get("status_code")
                            result["invalid_401"] = sc == 401
                            if sc == 200:
                                try:
                                    body_data = _safe_json(data.get("body", ""))
                                    used_pct = (body_data.get("rate_limit", {}).get("primary_window", {}).get("used_percent"))
                                    if used_pct is not None:
                                        result["used_percent"] = used_pct
                                        result["invalid_used_percent"] = used_pct >= self.used_percent_threshold
                                except Exception:
                                    pass
                            return result
                except Exception as e:
                    result["error"] = str(e)
                    if attempt >= retries:
                        return result
            return result

        async def delete_one(session: aiohttp.ClientSession, name: str) -> Dict[str, Any]:
            encoded = quote(name, safe="")
            try:
                async with semaphore:
                    async with session.delete(
                        f"{self.base_url}/v0/management/auth-files?name={encoded}",
                        headers=_mgmt_headers(self.token),
                        timeout=timeout,
                    ) as resp:
                        text = await resp.text()
                        data = _safe_json(text)
                        ok = resp.status == 200 and data.get("status") == "ok"
                        return {"name": name, "deleted": ok}
            except Exception:
                return {"name": name, "deleted": False}

        invalid_list = []
        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
            tasks = [asyncio.create_task(probe_one(session, item)) for item in candidates]
            for task in asyncio.as_completed(tasks):
                result = await task
                if result.get("invalid_401") or result.get("invalid_used_percent"):
                    invalid_list.append(result)

        return {
            "total": len(files),
            "candidates": len(candidates),
            "invalid": invalid_list,
            "files": files,
        }

    async def clean_invalid_async(self, workers: int = 20, timeout: int = 10, retries: int = 1) -> Dict[str, Any]:
        if aiohttp is None:
            raise RuntimeError("需要安装 aiohttp: pip install aiohttp")

        probe_result = await self.probe_accounts_async(workers, timeout, retries)
        invalid = probe_result["invalid"]
        names = [str(r["name"]) for r in invalid if r.get("name")]

        deleted_ok = 0
        deleted_fail = 0

        if names:
            semaphore = asyncio.Semaphore(max(1, workers))
            connector = aiohttp.TCPConnector(limit=max(1, workers))
            client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))

            async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
                async def do_delete(name: str) -> bool:
                    encoded = quote(name, safe="")
                    try:
                        async with semaphore:
                            async with session.delete(
                                f"{self.base_url}/v0/management/auth-files?name={encoded}",
                                headers=_mgmt_headers(self.token),
                                timeout=timeout,
                            ) as resp:
                                text = await resp.text()
                                data = _safe_json(text)
                                return resp.status == 200 and data.get("status") == "ok"
                    except Exception:
                        return False

                tasks = [asyncio.create_task(do_delete(n)) for n in names]
                for task in asyncio.as_completed(tasks):
                    if await task:
                        deleted_ok += 1
                    else:
                        deleted_fail += 1

        return {
            "total": probe_result["total"],
            "candidates": probe_result["candidates"],
            "invalid_count": len(invalid),
            "deleted_ok": deleted_ok,
            "deleted_fail": deleted_fail,
        }

    def probe_and_clean_sync(self, workers: int = 20, timeout: int = 10, retries: int = 1) -> Dict[str, Any]:
        return asyncio.run(self.clean_invalid_async(workers, timeout, retries))

    def calculate_gap(self, current_candidates: Optional[int] = None) -> int:
        if current_candidates is None:
            status = self.get_pool_status()
            if status.get("error"):
                raise RuntimeError(f"CPA 池状态查询失败: {status['error']}")
            current_candidates = status["candidates"]
        gap = self.min_candidates - current_candidates
        return max(0, gap)

    def upload_token(self, filename: str, token_data: Dict[str, Any], proxy: str = "") -> bool:
        if not self.base_url or not self.token:
            return False
        content = json.dumps(token_data, ensure_ascii=False).encode("utf-8")
        files = {"file": (filename, content, "application/json")}
        headers = {"Authorization": f"Bearer {self.token}"}
        
        with _build_session(proxy) as session:
            for attempt in range(3):
                try:
                    resp = session.post(
                        f"{self.base_url}/v0/management/auth-files",
                        files=files, headers=headers, verify=False, timeout=30,
                    )
                    if resp.status_code in (200, 201, 204):
                        return True
                except Exception:
                    pass
                if attempt < 2:
                    time.sleep(2 ** attempt)
        return False


class Sub2ApiMaintainer:
    """Sub2Api 平台池维护 — 通过 Admin API 管理账号池"""

    def __init__(
        self,
        base_url: str,
        bearer_token: str,
        min_candidates: int = 200,
        email: str = "",
        password: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.min_candidates = min_candidates
        self.email = email
        self.password = password
        self._auth_lock = threading.Lock()

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _login(self) -> str:
        with _build_session() as session:
            resp = session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"email": self.email, "password": self.password},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            token = (
                data.get("token")
                or data.get("access_token")
                or (data.get("data") or {}).get("token")
                or (data.get("data") or {}).get("access_token")
                or ""
            )
            if token:
                self.bearer_token = token
            return token

    def _request(self, method: str, path: str, **kwargs) -> _requests.Response:
        kwargs.setdefault("timeout", 15)
        url = f"{self.base_url}{path}"
        with _build_session() as session:
            resp = session.request(method, url, headers=self._headers(), **kwargs)
            if resp.status_code == 401 and self.email and self.password:
                current_token = self.bearer_token
                with self._auth_lock:
                    if self.bearer_token == current_token:
                        self._login()
                refreshed_token = self.bearer_token
                if refreshed_token or self.bearer_token != current_token:
                    resp = session.request(method, url, headers=self._headers(), **kwargs)
                    return resp
                resp = session.request(method, url, headers=self._headers(), **kwargs)
            return resp

    def get_dashboard_stats(self, timeout: int = 15) -> Dict[str, Any]:
        resp = self._request(
            "GET", "/api/v1/admin/dashboard/stats",
            params={"timezone": "Asia/Shanghai"}, timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data") if isinstance(data.get("data"), dict) else data

    def list_accounts(
        self, page: int = 1, page_size: int = 100, timeout: int = 15,
    ) -> Dict[str, Any]:
        params = {
            "page": page, "page_size": page_size,
            "platform": "openai", "type": "oauth",
        }
        resp = self._request(
            "GET", "/api/v1/admin/accounts",
            params=params, timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data") if isinstance(data.get("data"), dict) else data

    def _list_all_accounts(self, timeout: int = 15, page_size: int = 100) -> List[Dict[str, Any]]:
        all_accounts: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = self.list_accounts(page=page, page_size=page_size, timeout=timeout)
            items = data.get("items") or []
            if not isinstance(items, list):
                items = []
            all_accounts.extend([i for i in items if isinstance(i, dict)])
            if not items or len(items) < page_size:
                break
            total = data.get("total")
            if isinstance(total, int) and total > 0 and len(all_accounts) >= total:
                break
            page += 1
        return all_accounts

    def _account_identity(self, item: Dict[str, Any]) -> Dict[str, str]:
        email = ""
        rt = ""
        extra = item.get("extra")
        if isinstance(extra, dict):
            email = str(extra.get("email") or "").strip().lower()
        if not email:
            name = str(item.get("name") or "").strip().lower()
            if "@" in name:
                email = name
        creds = item.get("credentials")
        if isinstance(creds, dict):
            rt = str(creds.get("refresh_token") or "").strip()
        return {"email": email, "refresh_token": rt}

    @staticmethod
    def _account_sort_key(item: Dict[str, Any]) -> tuple[float, int]:
        updated = _parse_time_to_epoch(item.get("updated_at") or item.get("updatedAt"))
        try:
            item_id = int(item.get("id") or 0)
        except (TypeError, ValueError):
            item_id = 0
        return (updated, item_id)

    @staticmethod
    def _normalize_account_id(raw: Any) -> Optional[int]:
        try:
            account_id = int(raw)
        except (TypeError, ValueError):
            return None
        if account_id <= 0:
            return None
        return account_id

    @staticmethod
    def _is_abnormal_status(status: Any) -> bool:
        return str(status or "").strip().lower() in ("error", "disabled")

    def _build_dedupe_plan(self, all_accounts: List[Dict[str, Any]], details_limit: int = 120) -> Dict[str, Any]:
        id_to_account: Dict[int, Dict[str, Any]] = {}
        parent: Dict[int, int] = {}
        key_to_ids: Dict[str, List[int]] = {}

        for item in all_accounts:
            acc_id = self._normalize_account_id(item.get("id"))
            if acc_id is None:
                continue
            id_to_account[acc_id] = item
            parent[acc_id] = acc_id

            identity = self._account_identity(item)
            email = identity["email"]
            refresh_token = identity["refresh_token"]
            if email:
                key_to_ids.setdefault(f"email:{email}", []).append(acc_id)
            if refresh_token:
                key_to_ids.setdefault(f"rt:{refresh_token}", []).append(acc_id)

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
                for acc_id in ids[1:]:
                    union(head, acc_id)

        components: Dict[int, List[int]] = {}
        for acc_id in id_to_account.keys():
            root = find(acc_id)
            components.setdefault(root, []).append(acc_id)

        duplicate_groups = [ids for ids in components.values() if len(ids) > 1]
        delete_ids: List[int] = []
        group_details: List[Dict[str, Any]] = []

        for group_ids in duplicate_groups:
            group_items = [id_to_account[i] for i in group_ids]
            keep_item = max(group_items, key=self._account_sort_key)
            keep_id = self._normalize_account_id(keep_item.get("id")) or 0
            group_delete_ids = sorted([i for i in group_ids if i != keep_id], reverse=True)
            delete_ids.extend(group_delete_ids)

            if len(group_details) < details_limit:
                emails_set = set()
                for it in group_items:
                    identity = self._account_identity(it)
                    if identity["email"]:
                        emails_set.add(identity["email"])
                emails = sorted(emails_set)
                group_details.append({
                    "keep_id": keep_id,
                    "delete_ids": group_delete_ids,
                    "size": len(group_ids),
                    "emails": emails,
                })

        return {
            "duplicate_groups": len(duplicate_groups),
            "duplicate_accounts": sum(len(g) for g in duplicate_groups),
            "delete_ids": delete_ids,
            "groups_preview": group_details,
            "truncated_groups": max(0, len(duplicate_groups) - len(group_details)),
        }

    def list_account_inventory(self, timeout: int = 15) -> Dict[str, Any]:
        all_accounts = self._list_all_accounts(timeout=timeout, page_size=100)
        dedupe_plan = self._build_dedupe_plan(
            all_accounts,
            details_limit=max(1, len(all_accounts)),
        )
        duplicate_delete_ids = {
            int(account_id)
            for account_id in (dedupe_plan.get("delete_ids") or [])
            if isinstance(account_id, int)
        }
        duplicate_map: Dict[int, Dict[str, Any]] = {}
        for group in dedupe_plan.get("groups_preview") or []:
            keep_id = self._normalize_account_id(group.get("keep_id"))
            delete_ids = [
                account_id
                for account_id in (
                    self._normalize_account_id(item)
                    for item in (group.get("delete_ids") or [])
                )
                if account_id is not None
            ]
            group_ids = ([keep_id] if keep_id is not None else []) + delete_ids
            group_size = max(1, int(group.get("size") or len(group_ids) or 1))
            emails = [str(email).strip().lower() for email in (group.get("emails") or []) if str(email).strip()]
            for account_id in group_ids:
                duplicate_map[account_id] = {
                    "group_size": group_size,
                    "keep_id": keep_id,
                    "delete_candidate": account_id in duplicate_delete_ids,
                    "emails": emails,
                }

        items: List[Dict[str, Any]] = []
        abnormal_count = 0
        for raw_item in sorted(all_accounts, key=self._account_sort_key, reverse=True):
            account_id = self._normalize_account_id(raw_item.get("id"))
            if account_id is None:
                continue
            identity = self._account_identity(raw_item)
            status = str(raw_item.get("status") or "").strip().lower() or "unknown"
            if self._is_abnormal_status(status):
                abnormal_count += 1
            duplicate_info = duplicate_map.get(account_id) or {}
            items.append({
                "id": account_id,
                "name": str(raw_item.get("name") or "").strip(),
                "email": identity.get("email") or str(raw_item.get("name") or "").strip(),
                "status": status,
                "updated_at": raw_item.get("updated_at") or raw_item.get("updatedAt") or "",
                "created_at": raw_item.get("created_at") or raw_item.get("createdAt") or "",
                "is_duplicate": bool(duplicate_info),
                "duplicate_group_size": int(duplicate_info.get("group_size") or 0),
                "duplicate_keep": duplicate_info.get("keep_id") == account_id,
                "duplicate_delete_candidate": bool(duplicate_info.get("delete_candidate")),
                "duplicate_emails": duplicate_info.get("emails") or [],
            })

        return {
            "total": len(items),
            "error_count": abnormal_count,
            "duplicate_groups": int(dedupe_plan.get("duplicate_groups", 0)),
            "duplicate_accounts": int(dedupe_plan.get("duplicate_accounts", 0)),
            "items": items,
        }

    def _refresh_accounts_parallel(self, account_ids: List[int], timeout: int = 30, workers: int = 8) -> Dict[str, List[int]]:
        success_ids: List[int] = []
        failed_ids: List[int] = []
        ids = [i for i in account_ids if isinstance(i, int) and i > 0]
        if not ids:
            return {"success_ids": success_ids, "failed_ids": failed_ids}

        pool_workers = max(1, min(workers, 16, len(ids)))
        with ThreadPoolExecutor(max_workers=pool_workers) as executor:
            future_to_id = {
                executor.submit(self.refresh_account, account_id, timeout=timeout): account_id
                for account_id in ids
            }
            for future in as_completed(future_to_id):
                account_id = future_to_id[future]
                try:
                    ok = bool(future.result())
                except Exception:
                    ok = False
                if ok:
                    success_ids.append(account_id)
                else:
                    failed_ids.append(account_id)
        return {"success_ids": success_ids, "failed_ids": failed_ids}

    def _delete_accounts_parallel(self, account_ids: List[int], timeout: int = 15, workers: int = 12) -> Dict[str, Any]:
        deleted_ok_ids: List[int] = []
        failed_ids: List[int] = []
        unique_ids = sorted({i for i in account_ids if isinstance(i, int) and i > 0}, reverse=True)
        if not unique_ids:
            return {"deleted_ok": 0, "deleted_fail": 0, "deleted_ok_ids": deleted_ok_ids, "failed_ids": failed_ids}

        pool_workers = max(1, min(workers, 24, len(unique_ids)))
        with ThreadPoolExecutor(max_workers=pool_workers) as executor:
            future_to_id = {
                executor.submit(self.delete_account, account_id, timeout=timeout): account_id
                for account_id in unique_ids
            }
            for future in as_completed(future_to_id):
                account_id = future_to_id[future]
                try:
                    ok = bool(future.result())
                except Exception:
                    ok = False
                if ok:
                    deleted_ok_ids.append(account_id)
                else:
                    failed_ids.append(account_id)

        return {
            "deleted_ok": len(deleted_ok_ids),
            "deleted_fail": len(failed_ids),
            "deleted_ok_ids": deleted_ok_ids,
            "failed_ids": failed_ids,
        }

    def dedupe_duplicate_accounts(self, timeout: int = 15, dry_run: bool = True, details_limit: int = 120) -> Dict[str, Any]:
        """
        清理 Sub2Api 中 OpenAI OAuth 重复账号（按 email 或 refresh_token 判重）。
        - 同一连通重复组保留“最新”账号（updated_at 优先，其次 id 最大）。
        - dry_run=True 时仅预览，不执行删除。
        """
        all_accounts = self._list_all_accounts(timeout=timeout, page_size=100)
        dedupe_plan = self._build_dedupe_plan(all_accounts, details_limit=details_limit)
        delete_ids = dedupe_plan["delete_ids"]
        deleted_ok = 0
        deleted_fail = 0
        failed_ids: List[int] = []
        if not dry_run and delete_ids:
            delete_result = self._delete_accounts_parallel(delete_ids, timeout=timeout, workers=12)
            deleted_ok = int(delete_result.get("deleted_ok", 0))
            deleted_fail = int(delete_result.get("deleted_fail", 0))
            failed_ids = list(delete_result.get("failed_ids") or [])

        return {
            "dry_run": dry_run,
            "total": len(all_accounts),
            "duplicate_groups": int(dedupe_plan["duplicate_groups"]),
            "duplicate_accounts": int(dedupe_plan["duplicate_accounts"]),
            "to_delete": len(delete_ids),
            "deleted_ok": deleted_ok,
            "deleted_fail": deleted_fail,
            "failed_delete_ids": failed_ids[:200],
            "groups_preview": dedupe_plan["groups_preview"],
            "truncated_groups": int(dedupe_plan["truncated_groups"]),
        }

    def probe_accounts(self, account_ids: List[int], timeout: int = 30) -> Dict[str, Any]:
        ids = sorted({
            account_id
            for account_id in (
                self._normalize_account_id(item)
                for item in (account_ids or [])
            )
            if account_id is not None
        })
        if not ids:
            return {
                "requested": 0,
                "refreshed_ok": 0,
                "refreshed_fail": 0,
                "recovered": 0,
                "still_abnormal": 0,
                "details": [],
            }

        before_status = self._list_accounts_by_ids(ids, timeout=timeout)
        refresh_result = self._refresh_accounts_parallel(ids, timeout=max(30, timeout), workers=8)
        success_ids = set(refresh_result.get("success_ids") or [])
        failed_ids = set(refresh_result.get("failed_ids") or [])

        if success_ids:
            time.sleep(2)
        after_status = self._list_accounts_by_ids(ids, timeout=timeout)

        recovered_ids: List[int] = []
        abnormal_after_ids: List[int] = []
        details: List[Dict[str, Any]] = []
        for account_id in ids:
            before = str(before_status.get(account_id) or "unknown").strip().lower()
            after = str(after_status.get(account_id) or before or "unknown").strip().lower()
            if self._is_abnormal_status(before) and not self._is_abnormal_status(after):
                recovered_ids.append(account_id)
            if self._is_abnormal_status(after):
                abnormal_after_ids.append(account_id)
            if len(details) < 200:
                details.append({
                    "id": account_id,
                    "before_status": before,
                    "after_status": after,
                    "refresh_ok": account_id in success_ids,
                })

        return {
            "requested": len(ids),
            "refreshed_ok": len(success_ids),
            "refreshed_fail": len(failed_ids),
            "recovered": len(recovered_ids),
            "still_abnormal": len(abnormal_after_ids),
            "details": details,
        }

    def delete_accounts_batch(self, account_ids: List[int], timeout: int = 15) -> Dict[str, Any]:
        ids = [
            account_id
            for account_id in (
                self._normalize_account_id(item)
                for item in (account_ids or [])
            )
            if account_id is not None
        ]
        delete_result = self._delete_accounts_parallel(ids, timeout=timeout, workers=12)
        return {
            "requested": len({*ids}),
            "deleted_ok": int(delete_result.get("deleted_ok", 0)),
            "deleted_fail": int(delete_result.get("deleted_fail", 0)),
            "deleted_ok_ids": list(delete_result.get("deleted_ok_ids") or []),
            "failed_ids": list(delete_result.get("failed_ids") or []),
        }

    def handle_exception_accounts(
        self,
        account_ids: Optional[List[int]] = None,
        timeout: int = 30,
        delete_unresolved: bool = True,
    ) -> Dict[str, Any]:
        requested_ids = [
            account_id
            for account_id in (
                self._normalize_account_id(item)
                for item in (account_ids or [])
            )
            if account_id is not None
        ]

        if requested_ids:
            current_status = self._list_accounts_by_ids(requested_ids, timeout=timeout)
            target_ids = [
                account_id
                for account_id in requested_ids
                if self._is_abnormal_status(current_status.get(account_id))
            ]
            skipped_non_abnormal = max(0, len(set(requested_ids)) - len(target_ids))
        else:
            all_accounts = self._list_all_accounts(timeout=timeout, page_size=100)
            target_ids = [
                account_id
                for account_id in (
                    self._normalize_account_id(item.get("id"))
                    for item in all_accounts
                    if self._is_abnormal_status(item.get("status"))
                )
                if account_id is not None
            ]
            skipped_non_abnormal = 0

        unique_target_ids = sorted(set(target_ids))
        if not unique_target_ids:
            return {
                "requested": len(set(requested_ids)) if requested_ids else 0,
                "targeted": 0,
                "refreshed_ok": 0,
                "refreshed_fail": 0,
                "recovered": 0,
                "remaining_abnormal": 0,
                "deleted_ok": 0,
                "deleted_fail": 0,
                "skipped_non_abnormal": skipped_non_abnormal,
            }

        refresh_result = self._refresh_accounts_parallel(unique_target_ids, timeout=max(30, timeout), workers=8)
        if refresh_result.get("success_ids"):
            time.sleep(2)
        after_status = self._list_accounts_by_ids(unique_target_ids, timeout=timeout)
        remaining_abnormal_ids = [
            account_id
            for account_id in unique_target_ids
            if self._is_abnormal_status(after_status.get(account_id))
        ]
        remaining_abnormal_set = set(remaining_abnormal_ids)
        recovered_ids = [
            account_id
            for account_id in unique_target_ids
            if account_id not in remaining_abnormal_set
        ]

        delete_result = {
            "deleted_ok": 0,
            "deleted_fail": 0,
            "deleted_ok_ids": [],
            "failed_ids": [],
        }
        if delete_unresolved and remaining_abnormal_ids:
            delete_result = self._delete_accounts_parallel(remaining_abnormal_ids, timeout=timeout, workers=12)

        return {
            "requested": len(set(requested_ids)) if requested_ids else len(unique_target_ids),
            "targeted": len(unique_target_ids),
            "refreshed_ok": len(refresh_result.get("success_ids") or []),
            "refreshed_fail": len(refresh_result.get("failed_ids") or []),
            "recovered": len(recovered_ids),
            "remaining_abnormal": len(remaining_abnormal_ids),
            "deleted_ok": int(delete_result.get("deleted_ok", 0)),
            "deleted_fail": int(delete_result.get("deleted_fail", 0)),
            "deleted_ok_ids": list(delete_result.get("deleted_ok_ids") or []),
            "failed_ids": list(delete_result.get("failed_ids") or []),
            "skipped_non_abnormal": skipped_non_abnormal,
        }

    def refresh_account(self, account_id: int, timeout: int = 30) -> bool:
        try:
            resp = self._request(
                "POST", f"/api/v1/admin/accounts/{account_id}/refresh",
                timeout=timeout,
            )
            return resp.status_code in (200, 201)
        except Exception:
            return False

    def delete_account(self, account_id: int, timeout: int = 15) -> bool:
        try:
            resp = self._request(
                "DELETE", f"/api/v1/admin/accounts/{account_id}",
                timeout=timeout,
            )
            return resp.status_code in (200, 204)
        except Exception:
            return False

    def get_pool_status(self, timeout: int = 15) -> Dict[str, Any]:
        try:
            all_accounts = self._list_all_accounts(timeout=timeout, page_size=100)
            error = sum(
                1 for account in all_accounts
                if self._is_abnormal_status(account.get("status"))
            )
            total = len(all_accounts)
            normal = max(0, total - error)
            return {
                "total": total,
                "candidates": normal,
                "error_count": error,
                "threshold": self.min_candidates,
                "healthy": normal >= self.min_candidates,
                "percent": round(normal / self.min_candidates * 100, 1) if self.min_candidates > 0 else 100,
                "last_checked": time.strftime("%Y-%m-%d %H:%M:%S"),
                "error": None,
            }
        except Exception as e:
            return {
                "total": 0, "candidates": 0, "error_count": 0,
                "threshold": self.min_candidates, "healthy": False,
                "percent": 0, "last_checked": time.strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e),
            }

    def test_connection(self, timeout: int = 10) -> Dict[str, Any]:
        try:
            status = self.get_pool_status(timeout)
            total = int(status.get("total", 0))
            normal = int(status.get("candidates", 0))
            error = int(status.get("error_count", 0))
            return {
                "ok": True,
                "total": total,
                "normal": normal,
                "error": error,
                "message": f"连接成功，共 {total} 个账号，{normal} 正常，{error} 异常",
            }
        except Exception as e:
            return {"ok": False, "total": 0, "normal": 0, "error": 0,
                    "message": f"连接失败: {e}"}

    def _list_accounts_by_ids(
        self, ids: List[int], timeout: int = 15,
    ) -> Dict[int, str]:
        """查询指定 ID 的账号当前状态，返回 {id: status}"""
        result: Dict[int, str] = {}
        id_set = set(ids)
        page = 1
        while id_set:
            data = self.list_accounts(page=page, page_size=100, timeout=timeout)
            items = data.get("items") or []
            if not items:
                break
            for item in items:
                aid = item.get("id")
                if aid in id_set:
                    result[aid] = str(item.get("status", ""))
                    id_set.discard(aid)
            total = data.get("total", 0)
            if page * 100 >= total or len(items) < 100:
                break
            page += 1
        return result

    def probe_and_clean_sync(self, timeout: int = 15, actions: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
        action_flags = {
            "refresh_abnormal_accounts": bool((actions or {}).get("refresh_abnormal_accounts", True)),
            "delete_abnormal_accounts": bool((actions or {}).get("delete_abnormal_accounts", True)),
            "dedupe_duplicate_accounts": bool((actions or {}).get("dedupe_duplicate_accounts", True)),
        }
        started = time.time()
        all_accounts = self._list_all_accounts(timeout=timeout, page_size=100)

        error_accounts = [
            account for account in all_accounts
            if self._is_abnormal_status(account.get("status"))
        ]

        error_ids = [
            self._normalize_account_id(acc.get("id"))
            for acc in error_accounts
        ]
        error_ids = [i for i in error_ids if i is not None]
        initial_error_ids = set(error_ids)

        refresh_result = {"success_ids": [], "failed_ids": []}
        if action_flags["refresh_abnormal_accounts"] and error_ids:
            refresh_result = self._refresh_accounts_parallel(error_ids, timeout=30, workers=8)

        refreshed_ids = list(refresh_result.get("success_ids") or [])
        refresh_failed_ids = list(refresh_result.get("failed_ids") or [])

        current_accounts = all_accounts
        current_error_ids = set(initial_error_ids)
        if refreshed_ids:
            time.sleep(2)
        if action_flags["refresh_abnormal_accounts"] and (error_ids or refreshed_ids):
            current_accounts = self._list_all_accounts(timeout=timeout, page_size=100)
            current_error_ids = {
                int(acc_id) for acc_id in (
                    self._normalize_account_id(account.get("id"))
                    for account in current_accounts
                    if self._is_abnormal_status(account.get("status"))
                ) if isinstance(acc_id, int)
            }
        recovered = len(initial_error_ids - current_error_ids)

        dedupe_plan = {
            "duplicate_groups": 0,
            "duplicate_accounts": 0,
            "delete_ids": [],
            "groups_preview": [],
            "truncated_groups": 0,
        }
        duplicate_delete_ids: List[int] = []
        if action_flags["dedupe_duplicate_accounts"]:
            dedupe_plan = self._build_dedupe_plan(current_accounts, details_limit=120)
            duplicate_delete_ids = [int(i) for i in dedupe_plan["delete_ids"] if isinstance(i, int)]
        normal_count = len(current_accounts) - len(current_error_ids)

        delete_targets: set[int] = set()
        if action_flags["delete_abnormal_accounts"]:
            delete_targets.update(current_error_ids)
        if action_flags["dedupe_duplicate_accounts"]:
            delete_targets.update(duplicate_delete_ids)
        delete_result = self._delete_accounts_parallel(sorted(delete_targets, reverse=True), timeout=timeout, workers=12)
        deleted_ok = int(delete_result.get("deleted_ok", 0))
        deleted_fail = int(delete_result.get("deleted_fail", 0))
        deleted_ok_ids = set(int(i) for i in (delete_result.get("deleted_ok_ids") or []) if isinstance(i, int))

        deleted_from_error = len(deleted_ok_ids & set(current_error_ids))
        deleted_from_duplicate = len(deleted_ok_ids & set(duplicate_delete_ids))

        elapsed_ms = int((time.time() - started) * 1000)

        return {
            "actions": action_flags,
            "total": len(current_accounts), "normal": normal_count,
            "initial_error_count": len(initial_error_ids),
            "error_count": len(current_error_ids), "refreshed": recovered,
            "refresh_attempted": len(error_ids) if action_flags["refresh_abnormal_accounts"] else 0,
            "refresh_failed": len(refresh_failed_ids),
            "deleted_ok": deleted_ok, "deleted_fail": deleted_fail,
            "duplicate_groups": int(dedupe_plan["duplicate_groups"]),
            "duplicate_accounts": int(dedupe_plan["duplicate_accounts"]),
            "duplicate_to_delete": len(duplicate_delete_ids),
            "deleted_from_error": deleted_from_error,
            "deleted_from_duplicate": deleted_from_duplicate,
            "duration_ms": elapsed_ms,
        }

    def calculate_gap(self, current_candidates: Optional[int] = None) -> int:
        if current_candidates is None:
            status = self.get_pool_status()
            if status.get("error"):
                raise RuntimeError(f"Sub2Api 池状态查询失败: {status['error']}")
            current_candidates = status["candidates"]
        return max(0, self.min_candidates - current_candidates)
