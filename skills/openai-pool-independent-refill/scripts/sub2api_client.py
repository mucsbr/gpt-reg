from __future__ import annotations

import time
from typing import Any, Dict, List

from sub2api_api import (
    account_identity,
    account_sort_key,
    build_dedupe_plan,
    delete_account,
    get_dashboard_stats,
    is_abnormal_status,
    list_account_status_by_ids,
    list_all_accounts,
    refresh_account,
)


class Sub2ApiClient:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = bool(config.get("enabled", False))
        self.base_url = str(config.get("base_url") or "").strip()
        self.bearer_token = str(config.get("bearer_token") or "").strip()
        self.min_candidates = int(config.get("min_candidates") or 200)

    def get_dashboard_stats(self) -> Dict[str, Any]:
        return get_dashboard_stats(self.base_url, self.bearer_token)

    def get_status(self, timeout: int = 15) -> Dict[str, Any]:
        try:
            all_accounts = list_all_accounts(self.base_url, self.bearer_token, timeout=timeout, page_size=100)
            error_count = sum(1 for account in all_accounts if is_abnormal_status(account.get("status")))
            total = len(all_accounts)
            normal = max(0, total - error_count)
            return {
                "total": total,
                "candidates": normal,
                "error_count": error_count,
                "threshold": self.min_candidates,
                "healthy": normal >= self.min_candidates,
                "percent": round(normal / self.min_candidates * 100, 1) if self.min_candidates > 0 else 100,
                "error": None,
            }
        except Exception as exc:
            return {
                "total": 0,
                "candidates": 0,
                "error_count": 0,
                "threshold": self.min_candidates,
                "healthy": False,
                "percent": 0,
                "error": str(exc),
            }

    def calculate_gap(self, current_candidates: int | None = None) -> int:
        if current_candidates is None:
            status = self.get_status()
            if status.get("error"):
                raise RuntimeError(f"Sub2Api 池状态查询失败: {status['error']}")
            current_candidates = int(status.get("candidates", 0))
        return max(0, self.min_candidates - int(current_candidates))

    def list_accounts(self, timeout: int = 15) -> Dict[str, Any]:
        all_accounts = list_all_accounts(self.base_url, self.bearer_token, timeout=timeout, page_size=100)
        dedupe_plan = build_dedupe_plan(all_accounts, details_limit=max(1, len(all_accounts)))
        duplicate_delete_ids = {
            int(account_id)
            for account_id in (dedupe_plan.get("delete_ids") or [])
            if isinstance(account_id, int)
        }
        duplicate_map: Dict[int, Dict[str, Any]] = {}
        for group in dedupe_plan.get("groups_preview") or []:
            keep_id = group.get("keep_id")
            delete_ids = [account_id for account_id in (group.get("delete_ids") or []) if isinstance(account_id, int)]
            group_ids = ([keep_id] if isinstance(keep_id, int) else []) + delete_ids
            group_size = max(1, int(group.get("size") or len(group_ids) or 1))
            emails = [str(email).strip().lower() for email in (group.get("emails") or []) if str(email).strip()]
            for account_id in group_ids:
                duplicate_map[int(account_id)] = {
                    "group_size": group_size,
                    "keep_id": keep_id,
                    "delete_candidate": int(account_id) in duplicate_delete_ids,
                    "emails": emails,
                }

        items: List[Dict[str, Any]] = []
        abnormal_count = 0
        for raw_item in sorted(all_accounts, key=account_sort_key, reverse=True):
            try:
                account_id = int(raw_item.get("id") or 0)
            except (TypeError, ValueError):
                continue
            if account_id <= 0:
                continue
            identity = account_identity(raw_item)
            status = str(raw_item.get("status") or "").strip().lower() or "unknown"
            if is_abnormal_status(status):
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

    def classify_accounts(self, timeout: int = 15) -> Dict[str, Any]:
        inventory = self.list_accounts(timeout=timeout)
        items: List[Dict[str, Any]] = list(inventory.get("items") or [])
        return {
            "available": [item for item in items if item.get("status") not in {"error", "disabled"}],
            "abnormal": [item for item in items if item.get("status") in {"error", "disabled"}],
            "duplicates": [item for item in items if item.get("is_duplicate")],
            "errors": [],
            "raw": inventory,
        }

    def dedupe(self, timeout: int = 15, dry_run: bool = True) -> Dict[str, Any]:
        all_accounts = list_all_accounts(self.base_url, self.bearer_token, timeout=timeout, page_size=100)
        dedupe_plan = build_dedupe_plan(all_accounts, details_limit=120)
        delete_ids = [int(account_id) for account_id in (dedupe_plan.get("delete_ids") or []) if isinstance(account_id, int)]
        deleted_ok = 0
        deleted_fail = 0
        failed_ids: List[int] = []
        if not dry_run:
            for account_id in delete_ids:
                if delete_account(self.base_url, self.bearer_token, account_id, timeout=timeout):
                    deleted_ok += 1
                else:
                    deleted_fail += 1
                    failed_ids.append(account_id)
        return {
            "dry_run": dry_run,
            "total": len(all_accounts),
            "duplicate_groups": int(dedupe_plan.get("duplicate_groups", 0)),
            "duplicate_accounts": int(dedupe_plan.get("duplicate_accounts", 0)),
            "to_delete": len(delete_ids),
            "deleted_ok": deleted_ok,
            "deleted_fail": deleted_fail,
            "failed_delete_ids": failed_ids[:200],
            "groups_preview": dedupe_plan.get("groups_preview") or [],
            "truncated_groups": int(dedupe_plan.get("truncated_groups", 0)),
        }

    def probe_and_clean(self, timeout: int = 15, actions: Dict[str, bool] | None = None) -> Dict[str, Any]:
        action_flags = {
            "refresh_abnormal_accounts": bool((actions or {}).get("refresh_abnormal_accounts", True)),
            "delete_abnormal_accounts": bool((actions or {}).get("delete_abnormal_accounts", True)),
            "dedupe_duplicate_accounts": bool((actions or {}).get("dedupe_duplicate_accounts", True)),
        }
        started = time.time()
        inventory = self.list_accounts(timeout=timeout)
        items = list(inventory.get("items") or [])

        error_ids = [
            int(item["id"])
            for item in items
            if item.get("status") in {"error", "disabled"} and isinstance(item.get("id"), int)
        ]
        initial_error_ids = set(error_ids)

        refresh_success_ids: List[int] = []
        refresh_failed_ids: List[int] = []
        if action_flags["refresh_abnormal_accounts"]:
            for account_id in error_ids:
                if refresh_account(self.base_url, self.bearer_token, account_id, timeout=max(30, timeout)):
                    refresh_success_ids.append(account_id)
                else:
                    refresh_failed_ids.append(account_id)

        current_error_ids = set(initial_error_ids)
        if action_flags["refresh_abnormal_accounts"] and (error_ids or refresh_success_ids):
            if refresh_success_ids:
                time.sleep(2)
            current_status = list_account_status_by_ids(
                self.base_url,
                self.bearer_token,
                sorted(initial_error_ids),
                timeout=timeout,
            )
            current_error_ids = {
                account_id
                for account_id, status in current_status.items()
                if is_abnormal_status(status)
            }
        recovered = len(initial_error_ids - current_error_ids)

        dedupe_result = self.dedupe(
            timeout=timeout,
            dry_run=not action_flags["dedupe_duplicate_accounts"],
        )
        duplicate_delete_ids = [
            int(account_id)
            for account_id in ((dedupe_result.get("groups_preview") or []))
            for account_id in (account_id for account_id in (account_id for account_id in []))
        ]
        duplicate_delete_ids = [
            int(account_id)
            for account_id in (build_dedupe_plan(list_all_accounts(self.base_url, self.bearer_token, timeout=timeout, page_size=100), details_limit=120).get("delete_ids") or [])
            if isinstance(account_id, int)
        ] if action_flags["dedupe_duplicate_accounts"] else []

        deleted_ok = 0
        deleted_fail = 0
        deleted_from_error = 0
        deleted_from_duplicate = 0

        delete_targets: List[int] = []
        if action_flags["delete_abnormal_accounts"]:
            delete_targets.extend(sorted(current_error_ids, reverse=True))
        if action_flags["dedupe_duplicate_accounts"]:
            for account_id in duplicate_delete_ids:
                if account_id not in delete_targets:
                    delete_targets.append(account_id)

        for account_id in delete_targets:
            ok = delete_account(self.base_url, self.bearer_token, account_id, timeout=timeout)
            if ok:
                deleted_ok += 1
                if account_id in current_error_ids:
                    deleted_from_error += 1
                if account_id in duplicate_delete_ids:
                    deleted_from_duplicate += 1
            else:
                deleted_fail += 1

        elapsed_ms = int((time.time() - started) * 1000)
        return {
            "actions": action_flags,
            "total": int(inventory.get("total", 0)),
            "normal": max(0, int(inventory.get("total", 0)) - len(current_error_ids)),
            "initial_error_count": len(initial_error_ids),
            "error_count": len(current_error_ids),
            "refreshed": recovered,
            "refresh_attempted": len(error_ids) if action_flags["refresh_abnormal_accounts"] else 0,
            "refresh_failed": len(refresh_failed_ids),
            "deleted_ok": deleted_ok,
            "deleted_fail": deleted_fail,
            "duplicate_groups": int(dedupe_result.get("duplicate_groups", 0)),
            "duplicate_accounts": int(dedupe_result.get("duplicate_accounts", 0)),
            "duplicate_to_delete": int(dedupe_result.get("to_delete", 0)),
            "deleted_from_error": deleted_from_error,
            "deleted_from_duplicate": deleted_from_duplicate,
            "duration_ms": elapsed_ms,
            "note": "当前 skill 内 probe_and_clean 已补齐 refresh abnormal 基础语义，但仍未做并发 refresh 优化",
        }
