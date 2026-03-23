"""
FastAPI 后端服务
提供 REST API + SSE 实时日志推送
"""

import asyncio
import copy
import json
import re
import os
import queue
import random
import threading
import tempfile
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, TOKENS_DIR, CONFIG_FILE, STATE_FILE, STATIC_DIR, DATA_DIR
from .register import EventEmitter, _fetch_proxy_from_pool
from .mail_providers import create_provider, MultiMailRouter
from .pool_maintainer import PoolMaintainer, Sub2ApiMaintainer

# 动态导入注册函数（每次调用时读取配置，支持热切换）
def _get_run_function():
    """根据配置选择注册函数（支持 v1/v2/v3 动态切换）"""
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    version = cfg.get("use_register_version", "v1").lower()

    if version == "v2":
        from .register_v2 import run_v2
        return run_v2
    elif version == "v3":
        from .register_v3 import run_v3
        return run_v3
    else:  # v1 或其他值默认用 v1
        from .register import run
        return run

# ==========================================
# 同步配置（内存持久化到 data/sync_config.json）
# ==========================================

# CONFIG_FILE 和 TOKENS_DIR 已从包 __init__.py 导入


_config_lock = threading.RLock()
_service_shutdown_event = threading.Event()
_sub2api_accounts_cache_lock = threading.Lock()
_sub2api_accounts_cache: Dict[str, Any] = {
    "signature": "",
    "ts": 0.0,
    "inventory": None,
}

SUB2API_MAINTAIN_ACTION_DEFAULTS: Dict[str, bool] = {
    "refresh_abnormal_accounts": True,
    "delete_abnormal_accounts": True,
    "dedupe_duplicate_accounts": True,
}


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    return default


def _normalize_sub2api_maintain_actions(raw: Any) -> Dict[str, bool]:
    source = raw if isinstance(raw, dict) else {}
    return {
        key: _as_bool(source.get(key, default), default=default)
        for key, default in SUB2API_MAINTAIN_ACTION_DEFAULTS.items()
    }


def _get_sub2api_maintain_actions(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    config = cfg if cfg is not None else _get_sync_config()
    return _normalize_sub2api_maintain_actions(config.get("sub2api_maintain_actions"))


def _describe_sub2api_maintain_actions(actions: Optional[Dict[str, bool]] = None) -> str:
    normalized = _normalize_sub2api_maintain_actions(actions)
    labels: List[str] = []
    if normalized["refresh_abnormal_accounts"]:
        labels.append("异常测活")
    if normalized["delete_abnormal_accounts"]:
        labels.append("异常清理")
    if normalized["dedupe_duplicate_accounts"]:
        labels.append("重复清理")
    return "、".join(labels) if labels else "无动作"


def _format_sub2api_maintain_result_message(result: Dict[str, Any], *, auto: bool = False) -> str:
    prefix = "自动维护" if auto else "维护完成"
    actions_text = _describe_sub2api_maintain_actions(result.get("actions"))
    return (
        f"[Sub2Api] {prefix}({actions_text}): 异常 {result.get('error_count', 0)}, "
        f"刷新恢复 {result.get('refreshed', 0)}, "
        f"重复组 {result.get('duplicate_groups', 0)}, "
        f"删除 {result.get('deleted_ok', 0)}(失败 {result.get('deleted_fail', 0)}), "
        f"耗时 {round((result.get('duration_ms', 0) or 0) / 1000, 2)}s"
    )


def _clear_sub2api_accounts_cache() -> None:
    with _sub2api_accounts_cache_lock:
        _sub2api_accounts_cache["signature"] = ""
        _sub2api_accounts_cache["ts"] = 0.0
        _sub2api_accounts_cache["inventory"] = None


def _build_sub2api_accounts_cache_signature(cfg: Optional[Dict[str, Any]] = None) -> str:
    config = cfg or _get_sync_config()
    signature_payload = {
        "base_url": str(config.get("base_url", "") or "").strip(),
        "email": str(config.get("email", "") or "").strip().lower(),
        "sub2api_min_candidates": int(config.get("sub2api_min_candidates", 200) or 200),
    }
    return json.dumps(signature_payload, ensure_ascii=False, sort_keys=True)


def _get_sub2api_accounts_inventory_snapshot(
    sm: Sub2ApiMaintainer,
    cfg: Optional[Dict[str, Any]] = None,
    *,
    timeout: int = 15,
    ttl_seconds: int = 12,
) -> Dict[str, Any]:
    signature = _build_sub2api_accounts_cache_signature(cfg)
    now = time.time()
    with _sub2api_accounts_cache_lock:
        cached_signature = str(_sub2api_accounts_cache.get("signature") or "")
        cached_ts = float(_sub2api_accounts_cache.get("ts") or 0.0)
        cached_inventory = _sub2api_accounts_cache.get("inventory")
        if (
            cached_signature == signature
            and isinstance(cached_inventory, dict)
            and (now - cached_ts) <= ttl_seconds
        ):
            return copy.deepcopy(cached_inventory)

    inventory = sm.list_account_inventory(timeout=timeout)
    with _sub2api_accounts_cache_lock:
        _sub2api_accounts_cache["signature"] = signature
        _sub2api_accounts_cache["ts"] = now
        _sub2api_accounts_cache["inventory"] = copy.deepcopy(inventory)
    return inventory


def _filter_sub2api_account_items(items: List[Dict[str, Any]], status: str = "all", keyword: str = "") -> List[Dict[str, Any]]:
    normalized_status = str(status or "all").strip().lower() or "all"
    keyword_norm = str(keyword or "").strip().lower()
    abnormal_statuses = {"error", "disabled"}
    filtered: List[Dict[str, Any]] = []

    for item in items:
        item_status = str(item.get("status") or "").strip().lower()
        is_abnormal = item_status in abnormal_statuses
        is_duplicate = bool(item.get("is_duplicate"))

        if normalized_status == "normal" and is_abnormal:
            continue
        if normalized_status == "abnormal" and not is_abnormal:
            continue
        if normalized_status == "error" and item_status != "error":
            continue
        if normalized_status == "disabled" and item_status != "disabled":
            continue
        if normalized_status == "duplicate" and not is_duplicate:
            continue

        if keyword_norm:
            email = str(item.get("email") or "").lower()
            name = str(item.get("name") or "").lower()
            account_id = str(item.get("id") or "").lower()
            if keyword_norm not in email and keyword_norm not in name and keyword_norm not in account_id:
                continue

        filtered.append(item)

    return filtered


def _paginate_sub2api_account_items(
    items: List[Dict[str, Any]], page: int = 1, page_size: int = 20,
) -> Dict[str, Any]:
    safe_page_size = max(10, min(int(page_size or 20), 100))
    total = len(items)
    total_pages = max(1, (total + safe_page_size - 1) // safe_page_size)
    safe_page = max(1, min(int(page or 1), total_pages))
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return {
        "items": items[start:end],
        "page": safe_page,
        "page_size": safe_page_size,
        "filtered_total": total,
        "total_pages": total_pages,
    }


def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.stem}_", suffix=path.suffix, dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def _load_sync_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "base_url": "", "bearer_token": "", "account_name": "AutoReg", "auto_sync": False,
        "cpa_base_url": "", "cpa_token": "", "min_candidates": 800,
        "used_percent_threshold": 95, "auto_maintain": False, "maintain_interval_minutes": 30,
        "upload_mode": "snapshot",
        "mail_provider": "mailtm",
        "mail_config": {"api_base": "https://api.mail.tm", "api_key": "", "bearer_token": ""},
        "sub2api_min_candidates": 200,
        "sub2api_auto_maintain": False,
        "sub2api_maintain_interval_minutes": 30,
        "sub2api_maintain_actions": copy.deepcopy(SUB2API_MAINTAIN_ACTION_DEFAULTS),
        "proxy": "",
        "auto_register": False,
        "proxy_pool_enabled": True,
        "proxy_pool_api_url": "https://zenproxy.top/api/fetch",
        "proxy_pool_auth_mode": "query",
        "proxy_pool_api_key": "19c0ec43-8f76-4c97-81bc-bcda059eeba4",
        "proxy_pool_count": 1,
        "proxy_pool_country": "US",
    }


def _normalize_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """将旧的单邮箱提供商配置迁移到多提供商格式，含类型校验"""
    cfg = copy.deepcopy(cfg or {})
    legacy = str(cfg.get("mail_provider", "mailtm") or "mailtm").strip().lower()
    legacy_cfg = cfg.get("mail_config") or {}
    if not isinstance(legacy_cfg, dict):
        legacy_cfg = {}

    raw_providers = cfg.get("mail_providers")
    providers = raw_providers if isinstance(raw_providers, list) else []
    providers = [str(n).strip().lower() for n in providers if str(n).strip()]
    if not providers:
        providers = [legacy]

    raw_cfgs = cfg.get("mail_provider_configs")
    provider_cfgs = raw_cfgs if isinstance(raw_cfgs, dict) else {}
    for name in providers:
        if name not in provider_cfgs or not isinstance(provider_cfgs.get(name), dict):
            provider_cfgs[name] = {}
    if legacy in provider_cfgs:
        for k, v in legacy_cfg.items():
            provider_cfgs[legacy].setdefault(k, v)

    strategy = str(cfg.get("mail_strategy", "round_robin") or "round_robin").strip().lower()
    if strategy not in ("round_robin", "random", "failover"):
        strategy = "round_robin"

    cfg["mail_providers"] = providers
    cfg["mail_provider_configs"] = provider_cfgs
    cfg["mail_strategy"] = strategy
    cfg["mail_provider"] = providers[0]
    upload_mode = str(cfg.get("upload_mode", "snapshot") or "snapshot").strip().lower()
    if upload_mode not in ("snapshot", "decoupled"):
        upload_mode = "snapshot"
    cfg["upload_mode"] = upload_mode
    cfg["auto_sync"] = _as_bool(cfg.get("auto_sync", False), default=False)
    cfg["auto_maintain"] = _as_bool(cfg.get("auto_maintain", False), default=False)
    cfg["sub2api_auto_maintain"] = _as_bool(cfg.get("sub2api_auto_maintain", False), default=False)
    cfg["sub2api_maintain_actions"] = _normalize_sub2api_maintain_actions(cfg.get("sub2api_maintain_actions"))
    cfg["multithread"] = _as_bool(cfg.get("multithread", False), default=False)
    cfg["auto_register"] = _as_bool(cfg.get("auto_register", False), default=False)
    try:
        cfg["thread_count"] = max(1, min(int(cfg.get("thread_count", 3)), 10))
    except (ValueError, TypeError):
        cfg["thread_count"] = 3
    cfg["proxy_pool_enabled"] = _as_bool(cfg.get("proxy_pool_enabled", True), default=True)
    proxy_pool_api_url = str(cfg.get("proxy_pool_api_url", "https://zenproxy.top/api/fetch") or "").strip()
    cfg["proxy_pool_api_url"] = proxy_pool_api_url or "https://zenproxy.top/api/fetch"
    proxy_pool_auth_mode = str(cfg.get("proxy_pool_auth_mode", "query") or "").strip().lower()
    if proxy_pool_auth_mode not in ("header", "query"):
        proxy_pool_auth_mode = "query"
    cfg["proxy_pool_auth_mode"] = proxy_pool_auth_mode
    cfg["proxy_pool_api_key"] = str(cfg.get("proxy_pool_api_key", "19c0ec43-8f76-4c97-81bc-bcda059eeba4") or "").strip()
    try:
        cfg["proxy_pool_count"] = max(1, min(int(cfg.get("proxy_pool_count", 1)), 20))
    except (TypeError, ValueError):
        cfg["proxy_pool_count"] = 1
    cfg["proxy_pool_country"] = str(cfg.get("proxy_pool_country", "US") or "US").strip().upper() or "US"
    return cfg


def _pool_relay_url_from_fetch_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        from urllib.parse import urlparse
        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc
        if not netloc:
            return ""
        return f"{scheme}://{netloc}/api/relay"
    except Exception:
        return ""


def _get_sync_config() -> Dict[str, Any]:
    with _config_lock:
        return copy.deepcopy(_sync_config)


def _set_sync_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    global _sync_config
    normalized = _normalize_config(cfg)
    with _config_lock:
        _write_json_atomic(CONFIG_FILE, normalized)
        _sync_config = normalized
        return copy.deepcopy(_sync_config)


def _save_sync_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return _set_sync_config(cfg)


_sync_config = _normalize_config(_load_sync_config())


def _is_auto_sync_enabled(cfg: Optional[Dict[str, Any]] = None) -> bool:
    config = cfg if cfg is not None else _get_sync_config()
    return _as_bool(config.get("auto_sync", False), default=False)


def _push_refresh_token(base_url: str, bearer: str, refresh_token: str) -> Dict[str, Any]:
    """
    调用 Sub2Api 平台 API 提交单个 refresh_token。
    返回 {ok: bool, status: int, body: str}
    """
    url = base_url.rstrip("/") + "/api/v1/admin/openai/refresh-token"
    payload = json.dumps({"refresh_token": refresh_token}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", "replace")
            return {"ok": True, "status": resp.status, "body": body}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return {"ok": False, "status": exc.code, "body": body}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)}


UPLOAD_PLATFORMS = ("cpa", "sub2api")


def _extract_uploaded_platforms(token_data: Dict[str, Any]) -> List[str]:
    platforms = set()
    raw_platforms = token_data.get("uploaded_platforms")
    if isinstance(raw_platforms, list):
        for p in raw_platforms:
            name = str(p).strip().lower()
            if name in UPLOAD_PLATFORMS:
                platforms.add(name)
    if token_data.get("cpa_uploaded") or token_data.get("cpa_synced"):
        platforms.add("cpa")
    if token_data.get("sub2api_uploaded") or token_data.get("sub2api_synced") or token_data.get("synced"):
        platforms.add("sub2api")
    return [p for p in UPLOAD_PLATFORMS if p in platforms]


def _is_sub2api_uploaded(token_data: Dict[str, Any]) -> bool:
    return "sub2api" in _extract_uploaded_platforms(token_data)


def _mark_token_uploaded_platform(file_path: str, platform: str) -> bool:
    platform_name = str(platform).strip().lower()
    if platform_name not in UPLOAD_PLATFORMS:
        return False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            token_data = json.load(f)
        if not isinstance(token_data, dict):
            return False

        platforms = _extract_uploaded_platforms(token_data)
        if platform_name not in platforms:
            platforms.append(platform_name)
        token_data["uploaded_platforms"] = [p for p in UPLOAD_PLATFORMS if p in set(platforms)]
        token_data[f"{platform_name}_uploaded"] = True
        token_data[f"{platform_name}_synced"] = True

        if platform_name == "sub2api":
            token_data["synced"] = True  # 兼容旧前端逻辑

        uploaded_at = token_data.get("uploaded_at")
        if not isinstance(uploaded_at, dict):
            uploaded_at = {}
        uploaded_at[platform_name] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        token_data["uploaded_at"] = uploaded_at

        _write_json_atomic(Path(file_path), token_data)
        return True
    except Exception:
        return False


# ==========================================
# 统计数据持久化
# ==========================================

# STATE_FILE 已从包 __init__.py 导入


def _load_state() -> Dict[str, int]:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"success": 0, "fail": 0}


def _save_state(success: int, fail: int) -> None:
    try:
        _write_json_atomic(STATE_FILE, {"success": success, "fail": fail})
    except Exception:
        pass


# ==========================================
# 应用初始化
# ==========================================

app = FastAPI(title="OpenAI Pool Orchestrator", version=__version__)

# STATIC_DIR 和 TOKENS_DIR 已从包 __init__.py 导入
STATIC_DIR.mkdir(exist_ok=True)
os.makedirs(str(TOKENS_DIR), exist_ok=True)

# ==========================================
# 任务状态管理
# ==========================================


class TaskState:
    """全局任务状态，支持多 Worker 运行快照与结构化 SSE 事件。"""

    _WORKER_STEP_DEFINITIONS = {
        "check_proxy": "网络检查",
        "create_email": "创建邮箱",
        "oauth_init": "OAuth 初始化",
        "sentinel": "Sentinel Token",
        "signup": "提交注册",
        "send_otp": "发送验证码",
        "wait_otp": "等待验证码",
        "verify_otp": "验证 OTP",
        "create_account": "创建账户",
        "workspace": "选择 Workspace",
        "get_token": "获取 Token",
        "saved": "保存 Token",
        "cpa_upload": "上传 CPA",
        "sync": "同步 Sub2Api",
        "retry": "等待重试",
        "wait": "等待下一轮",
        "dedupe": "重复检测",
        "runtime": "运行异常",
        "auto_stop": "自动停止",
        "stopping": "停止中",
        "stopped": "已停止",
        "mode": "上传策略",
        "shutdown": "服务关闭",
    }
    _REGISTRATION_STEPS = frozenset({
        "check_proxy", "create_email", "oauth_init", "sentinel",
        "signup", "send_otp", "wait_otp", "verify_otp",
        "create_account", "workspace", "get_token",
    })

    def __init__(self) -> None:
        self.status: str = "stopped"
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self._worker_threads: Dict[int, threading.Thread] = {}
        self._task_lock = threading.RLock()
        self._sse_queues: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self._sse_lock = threading.Lock()

        _s = _load_state()
        self.success_count: int = int(_s.get("success", 0) or 0)
        self.fail_count: int = int(_s.get("fail", 0) or 0)
        self.current_proxy: str = ""
        self.worker_count: int = 0
        self.upload_mode: str = "snapshot"
        self.target_count: int = 0
        self.run_success_count: int = 0
        self.run_fail_count: int = 0
        self.platform_success_count: Dict[str, int] = {name: 0 for name in UPLOAD_PLATFORMS}
        self.platform_fail_count: Dict[str, int] = {name: 0 for name in UPLOAD_PLATFORMS}
        self.platform_backlog_count: Dict[str, int] = {name: 0 for name in UPLOAD_PLATFORMS}
        self._upload_queues: Dict[str, queue.Queue] = {}

        self.run_id: Optional[str] = None
        self.revision: int = 0
        self.created_at: Optional[str] = None
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.stop_reason: str = ""
        self.last_error: str = ""
        self.completion_semantics: str = "registration_only"
        self._focus_worker_id: Optional[int] = None
        self._worker_runtime: Dict[int, Dict[str, Any]] = {}

    def _now_iso(self) -> str:
        return datetime.now().isoformat(timespec="seconds")

    def _new_run_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def _next_revision_locked(self) -> int:
        self.revision += 1
        return self.revision

    def _completion_semantics_locked(self) -> str:
        return "requires_postprocess" if _is_auto_sync_enabled() else "registration_only"

    def _empty_worker_runtime_locked(self, worker_id: int, worker_label: Optional[str] = None) -> Dict[str, Any]:
        return {
            "worker_id": worker_id,
            "worker_label": worker_label or f"W{worker_id}",
            "status": "starting",
            "phase": "prepare",
            "attempt": 0,
            "mail_provider": "",
            "account_email": "",
            "current_step": "",
            "message": "",
            "updated_at": self._now_iso(),
            "steps": [],
        }

    def _empty_runtime_snapshot_locked(self) -> Dict[str, Any]:
        workers = [
            copy.deepcopy(runtime)
            for _, runtime in sorted(self._worker_runtime.items(), key=lambda item: item[0])
        ]
        return {
            "run_id": self.run_id,
            "revision": self.revision,
            "completion_semantics": self.completion_semantics,
            "focus_worker_id": self._focus_worker_id,
            "aggregate": self._aggregate_runtime_locked(),
            "workers": workers,
        }

    def _task_snapshot_locked(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "revision": self.revision,
            "status": self.status,
            "worker_count": self.worker_count,
            "upload_mode": self.upload_mode,
            "completion_semantics": self.completion_semantics,
            "target_count": self.target_count,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stop_reason": self.stop_reason,
            "last_error": self.last_error,
            "proxy": self.current_proxy,
        }

    def _stats_snapshot_locked(self) -> Dict[str, Any]:
        platform = {}
        for name in UPLOAD_PLATFORMS:
            success = int(self.platform_success_count.get(name, 0) or 0)
            fail = int(self.platform_fail_count.get(name, 0) or 0)
            backlog = int(self.platform_backlog_count.get(name, 0) or 0)
            platform[name] = {
                "success": success,
                "fail": fail,
                "backlog": backlog,
                "total": success + fail,
            }
        return {
            "lifetime": {
                "success": self.success_count,
                "fail": self.fail_count,
                "total": self.success_count + self.fail_count,
            },
            "run": {
                "success": self.run_success_count,
                "fail": self.run_fail_count,
                "total": self.run_success_count + self.run_fail_count,
            },
            "platform": platform,
            "success": self.success_count,
            "fail": self.fail_count,
            "total": self.success_count + self.fail_count,
        }

    def _status_snapshot_locked(self) -> Dict[str, Any]:
        return {
            "task": self._task_snapshot_locked(),
            "runtime": self._empty_runtime_snapshot_locked(),
            "stats": self._stats_snapshot_locked(),
            "server_time": self._now_iso(),
        }

    def get_status_snapshot(self) -> Dict[str, Any]:
        with self._task_lock:
            return self._status_snapshot_locked()

    def subscribe(self) -> asyncio.Queue:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        with self._sse_lock:
            self._sse_queues.append((loop, q))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._sse_lock:
            self._sse_queues = [(loop, queue_obj) for loop, queue_obj in self._sse_queues if queue_obj is not q]

    def _enqueue_sse_payload(self, payload: Dict[str, Any]) -> None:
        with self._sse_lock:
            subscribers = list(self._sse_queues)
        for loop, q in subscribers:
            def _enqueue(target_q: asyncio.Queue = q, data: Dict[str, Any] = payload) -> None:
                try:
                    target_q.put_nowait(copy.deepcopy(data))
                except asyncio.QueueFull:
                    pass
            try:
                loop.call_soon_threadsafe(_enqueue)
            except RuntimeError:
                continue

    def _emit_event_locked(self, event_type: str, payload: Optional[Dict[str, Any]] = None, *, bump_revision: bool = False) -> Dict[str, Any]:
        if bump_revision:
            self._next_revision_locked()
        event_payload: Dict[str, Any] = {
            "type": event_type,
            "run_id": self.run_id,
            "revision": self.revision,
        }
        if payload:
            event_payload.update(payload)
        self._enqueue_sse_payload(event_payload)
        return event_payload

    def _sync_status_from_workers_locked(self) -> None:
        if self.status in {"stopping", "stopped", "finished"}:
            return
        workers = list(self._worker_runtime.values())
        if not workers:
            return
        statuses = {str(worker.get("status") or "") for worker in workers}
        if any(status == "failed" for status in statuses):
            self.status = "failed"
            return
        if statuses and statuses.issubset({"succeeded", "stopped"}):
            self.status = "finished"
            return
        self.status = "running"

    def _finalize_worker_runtimes_locked(self, final_status: str) -> None:
        status = str(final_status or "").strip().lower()
        if status != "stopped":
            return
        updated_at = self._now_iso()
        for runtime in self._worker_runtime.values():
            runtime["status"] = "stopped"
            runtime["phase"] = "finish"
            runtime["current_step"] = "stopped"
            runtime["message"] = "任务已停止"
            runtime["updated_at"] = updated_at
            self._upsert_worker_step_locked(
                runtime,
                step_id="stopped",
                level="info",
                message="任务已停止",
                updated_at=updated_at,
            )

    def _worker_status_from_step(self, step: str, level: str) -> str:
        s = str(step or "").strip().lower()
        lv = str(level or "").strip().lower()
        if s in {"stopping"}:
            return "stopping"
        if s in {"stopped", "auto_stop"}:
            return "stopped"
        if s in {"retry", "wait"}:
            return "waiting"
        if s == "runtime" or lv == "error":
            return "failed"
        if s in {"cpa_upload", "sync", "saved"}:
            return "postprocessing"
        if s in {"start", "dedupe", "mode"}:
            return "preparing"
        if s in self._REGISTRATION_STEPS:
            if s == "get_token" and lv == "success":
                return "succeeded" if self.completion_semantics == "registration_only" else "postprocessing"
            return "registering"
        return "running" if self.status in {"running", "starting"} else self.status

    def _worker_phase_from_step(self, step: str) -> str:
        s = str(step or "").strip().lower()
        if s in {"start", "dedupe", "mode"}:
            return "prepare"
        if s in self._REGISTRATION_STEPS:
            return "register"
        if s in {"saved", "cpa_upload", "sync", "retry", "wait"}:
            return "postprocess"
        if s in {"stopping", "stopped", "auto_stop", "shutdown"}:
            return "finish"
        return "prepare"

    def _extract_email_from_event(self, event: Dict[str, Any]) -> str:
        direct_email = str(event.get("account_email") or "").strip()
        if direct_email:
            return direct_email
        message = str(event.get("message") or "")
        match = re.search(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", message)
        return match.group(1) if match else ""

    def _upsert_worker_step_locked(self, runtime: Dict[str, Any], *, step_id: str, level: str, message: str, updated_at: str) -> Dict[str, Any]:
        label = self._WORKER_STEP_DEFINITIONS.get(step_id, step_id or "运行步骤")
        raw_status = str(level or "info").strip().lower()
        if raw_status == "success":
            status = "done"
        elif raw_status == "error":
            status = "error"
        elif step_id in {"wait", "retry"}:
            status = "active"
        else:
            status = "active"
        steps: List[Dict[str, Any]] = runtime.setdefault("steps", [])
        current = None
        for item in steps:
            if item.get("step_id") == step_id:
                current = item
                break
        if current is None:
            current = {
                "step_id": step_id,
                "id": step_id,
                "label": label,
                "status": status,
                "message": message,
                "started_at": updated_at,
                "finished_at": updated_at if status in {"done", "error", "skipped"} else None,
                "updated_at": updated_at,
            }
            steps.append(current)
        else:
            current["label"] = label
            current["status"] = status
            current["message"] = message
            current["updated_at"] = updated_at
            current.setdefault("started_at", updated_at)
            if status in {"done", "error", "skipped"}:
                current["finished_at"] = updated_at
            else:
                current["finished_at"] = None
        return copy.deepcopy(current)

    def _update_runtime_from_event_locked(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw_worker_id = event.get("worker_id")
        try:
            worker_id = int(raw_worker_id)
        except (TypeError, ValueError):
            return None

        runtime = self._worker_runtime.get(worker_id)
        if runtime is None:
            runtime = self._empty_worker_runtime_locked(worker_id, str(event.get("worker_label") or f"W{worker_id}"))
            self._worker_runtime[worker_id] = runtime

        updated_at = str(event.get("iso_ts") or event.get("updated_at") or self._now_iso())
        runtime["updated_at"] = updated_at
        runtime["worker_label"] = str(event.get("worker_label") or runtime.get("worker_label") or f"W{worker_id}")

        attempt = event.get("attempt")
        if attempt not in (None, ""):
            try:
                runtime["attempt"] = int(attempt)
            except (TypeError, ValueError):
                pass

        mail_provider = str(event.get("mail_provider") or "").strip()
        if mail_provider:
            runtime["mail_provider"] = mail_provider

        email = self._extract_email_from_event(event)
        if email:
            runtime["account_email"] = email
            runtime["email"] = email

        message = str(event.get("message") or "").strip()
        if message:
            runtime["message"] = message

        step = str(event.get("step") or "").strip().lower()
        level = str(event.get("level") or "info").strip().lower()
        step_patch = None
        if step:
            runtime["current_step"] = step
            runtime["phase"] = self._worker_phase_from_step(step)
            runtime["status"] = self._worker_status_from_step(step, level)
            step_patch = self._upsert_worker_step_locked(runtime, step_id=step, level=level, message=message, updated_at=updated_at)
            if step == "start":
                runtime["steps"] = [step_patch]
            if step in {"stopped", "auto_stop"}:
                runtime["status"] = "stopped"
            elif step == "runtime" or (level == "error" and step not in {"retry", "wait"}):
                runtime["status"] = "failed"
        else:
            runtime["status"] = "running" if self.status not in {"stopping", "stopped"} else self.status

        if self._focus_worker_id is None or self._focus_worker_id == worker_id:
            self._focus_worker_id = worker_id
        elif runtime["status"] in {"registering", "postprocessing", "failed", "waiting"}:
            self._focus_worker_id = worker_id

        self._sync_status_from_workers_locked()
        return {
            "worker": copy.deepcopy(runtime),
            "step": step_patch,
        }

    def _aggregate_runtime_locked(self) -> Dict[str, Any]:
        agg: Dict[str, Any] = {
            "total": 0,
            "starting": 0,
            "preparing": 0,
            "registering": 0,
            "postprocessing": 0,
            "waiting": 0,
            "stopping": 0,
            "stopped": 0,
            "failed": 0,
            "succeeded": 0,
            "last_updated_at": None,
        }
        for runtime in self._worker_runtime.values():
            agg["total"] += 1
            status = str(runtime.get("status") or "").strip().lower()
            if status in agg:
                agg[status] += 1
            updated_at = runtime.get("updated_at")
            if updated_at and (agg["last_updated_at"] is None or str(updated_at) > str(agg["last_updated_at"])):
                agg["last_updated_at"] = updated_at
        return agg

    def broadcast(self, event: Dict[str, Any]) -> None:
        with self._task_lock:
            payload = dict(event)
            payload.setdefault("ts", datetime.now().strftime("%H:%M:%S"))
            payload.setdefault("iso_ts", self._now_iso())
            event_type = str(payload.get("type") or "").strip()
            if event_type:
                self._emit_event_locked(event_type, payload, bump_revision=event_type != "heartbeat")
                return

            runtime_patch = self._update_runtime_from_event_locked(payload)
            self._emit_event_locked(
                "log.appended",
                {
                    "log": {
                        "ts": payload.get("ts", ""),
                        "level": payload.get("level", "info"),
                        "message": payload.get("message", ""),
                        "step": payload.get("step", ""),
                        "worker_id": payload.get("worker_id"),
                        "worker_label": payload.get("worker_label"),
                    }
                },
                bump_revision=True,
            )
            if runtime_patch:
                self._emit_event_locked("worker.updated", {"worker": runtime_patch["worker"]})
                if runtime_patch.get("step"):
                    self._emit_event_locked(
                        "worker.step.updated",
                        {
                            "worker_id": runtime_patch["worker"].get("worker_id"),
                            "worker": runtime_patch["worker"],
                            "step": runtime_patch["step"],
                            "focus_worker_id": self._focus_worker_id,
                        },
                    )
                self._emit_event_locked("task.updated", {"task": self._task_snapshot_locked()})
                self._emit_event_locked("stats.updated", {"stats": self._stats_snapshot_locked()})

    def _make_emitter(self) -> EventEmitter:
        thread_q: queue.Queue = queue.Queue(maxsize=500)

        def _bridge() -> None:
            while True:
                try:
                    event = thread_q.get(timeout=0.2)
                    if event is None:
                        break
                    try:
                        self.broadcast(event)
                    except Exception as exc:
                        try:
                            print(f"[bridge] log event dropped: {exc}")
                        except Exception:
                            pass
                except queue.Empty:
                    if self.stop_event.is_set() and thread_q.empty():
                        break

        bridge_thread = threading.Thread(target=_bridge, daemon=True)
        bridge_thread.start()
        self._bridge_thread = bridge_thread
        self._bridge_q = thread_q
        return EventEmitter(q=thread_q, cli_mode=True)

    def _stop_bridge(self) -> None:
        if hasattr(self, "_bridge_q"):
            try:
                self._bridge_q.put_nowait(None)
            except queue.Full:
                pass

    def start_task(
        self,
        proxy: str,
        worker_count: int = 1,
        target_count: int = 0,
        cpa_target_count: Optional[int] = None,
        sub2api_target_count: Optional[int] = None,
    ) -> None:
        cpa_target = None if cpa_target_count is None else max(0, int(cpa_target_count))
        sub2api_target = None if sub2api_target_count is None else max(0, int(sub2api_target_count))
        config_snapshot = _get_sync_config()
        upload_mode = str(config_snapshot.get("upload_mode", "snapshot") or "snapshot").strip().lower()
        if upload_mode not in ("snapshot", "decoupled"):
            upload_mode = "snapshot"
        try:
            mail_router = MultiMailRouter(config_snapshot)
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
        pool_maintainer = _get_pool_maintainer(config_snapshot)
        auto_sync_enabled = _is_auto_sync_enabled(config_snapshot)

        with self._task_lock:
            if self.status in ("starting", "running", "stopping"):
                raise RuntimeError("任务正在运行或停止中")
            n = max(1, min(int(worker_count or 1), 10))
            now = self._now_iso()
            self.run_id = self._new_run_id()
            self.revision = 0
            self.status = "starting"
            self.stop_event.clear()
            self.current_proxy = proxy
            self.worker_count = n
            self.upload_mode = upload_mode
            self.target_count = max(0, target_count)
            self.run_success_count = 0
            self.run_fail_count = 0
            self.platform_success_count = {name: 0 for name in UPLOAD_PLATFORMS}
            self.platform_fail_count = {name: 0 for name in UPLOAD_PLATFORMS}
            self.platform_backlog_count = {name: 0 for name in UPLOAD_PLATFORMS}
            self._upload_queues = {}
            self._worker_threads = {}
            self._worker_runtime = {
                wid: self._empty_worker_runtime_locked(wid)
                for wid in range(1, n + 1)
            }
            self._focus_worker_id = 1 if n > 0 else None
            self.created_at = now
            self.started_at = now
            self.finished_at = None
            self.stop_reason = ""
            self.last_error = ""
            self.completion_semantics = "requires_postprocess" if auto_sync_enabled else "registration_only"
            self._emit_event_locked("task.updated", {"task": self._task_snapshot_locked()}, bump_revision=True)
            self._emit_event_locked("snapshot", {"snapshot": self._status_snapshot_locked()})

        emitter = self._make_emitter()
        emitter.info(
            f"上传策略: {'串行补平台（先CPA后Sub2Api）' if upload_mode == 'snapshot' else '双平台同传（单账号双上传）'}",
            step="mode",
        )


        upload_remaining: Dict[str, Optional[int]] = {
            "cpa": cpa_target,
            "sub2api": sub2api_target,
        }
        snapshot_strict_serial = (
            upload_mode == "snapshot"
            and cpa_target is not None
            and sub2api_target is not None
        )
        token_states: Dict[str, Dict[str, Any]] = {}
        token_states_lock = threading.RLock()
        seen_runtime_identities: set[str] = _load_local_token_identity_keys()
        seen_runtime_identities_lock = threading.RLock()
        upload_queues: Dict[str, queue.Queue] = {}
        upload_workers: Dict[str, threading.Thread] = {}
        producers_done = threading.Event()

        def _reserve_upload_slot(platform: str) -> bool:
            with self._task_lock:
                remain = upload_remaining.get(platform)
                if remain is None:
                    return True
                if remain <= 0:
                    return False
                upload_remaining[platform] = remain - 1
                return True

        def _release_upload_slot(platform: str) -> None:
            with self._task_lock:
                remain = upload_remaining.get(platform)
                if remain is not None:
                    upload_remaining[platform] = remain + 1

        def _decoupled_slots_exhausted() -> bool:
            """仅在双平台同传 + 有限配额场景下判断是否已无可用上传槽位。"""
            if upload_mode != "decoupled":
                return False
            with self._task_lock:
                finite_remains = [
                    remain
                    for remain in upload_remaining.values()
                    if remain is not None
                ]
            return bool(finite_remains) and all(remain <= 0 for remain in finite_remains)

        def _reserve_snapshot_serial_platform() -> Optional[str]:
            with self._task_lock:
                cpa_remain = upload_remaining.get("cpa")
                if cpa_remain is not None and cpa_remain > 0:
                    upload_remaining["cpa"] = cpa_remain - 1
                    return "cpa"
                sub2api_remain = upload_remaining.get("sub2api")
                if sub2api_remain is not None and sub2api_remain > 0:
                    upload_remaining["sub2api"] = sub2api_remain - 1
                    return "sub2api"
            return None

        def _record_platform_result(platform: str, ok: bool) -> None:
            if platform not in UPLOAD_PLATFORMS:
                return
            with self._task_lock:
                if ok:
                    self.platform_success_count[platform] = self.platform_success_count.get(platform, 0) + 1
                else:
                    self.platform_fail_count[platform] = self.platform_fail_count.get(platform, 0) + 1

        def _register_runtime_identity(email: str, refresh_token: str) -> bool:
            keys = _sub2api_identity_keys(email=email, refresh_token=refresh_token)
            if not keys:
                return True
            with seen_runtime_identities_lock:
                for key in keys:
                    if key in seen_runtime_identities:
                        return False
                seen_runtime_identities.update(keys)
            return True

        def _refresh_backlog() -> None:
            with self._task_lock:
                if upload_mode != "decoupled":
                    self.platform_backlog_count = {name: 0 for name in UPLOAD_PLATFORMS}
                    return
                self.platform_backlog_count = {
                    platform: q.qsize()
                    for platform, q in upload_queues.items()
                }

        def _apply_final_result(email: str, prefix: str, ok: bool) -> None:
            if ok:
                with self._task_lock:
                    self.success_count += 1
                    self.run_success_count += 1
                    _save_state(self.success_count, self.fail_count)
                    should_stop = self.target_count > 0 and self.run_success_count >= self.target_count
                if should_stop:
                    emitter.success(
                        f"{prefix}本轮已达目标 {self.target_count} 个，自动停止",
                        step="auto_stop",
                    )
                    self.stop_event.set()
            else:
                with self._task_lock:
                    self.fail_count += 1
                    self.run_fail_count += 1
                    _save_state(self.success_count, self.fail_count)
                emitter.error(f"{prefix}平台上传未完成，本次不计入成功: {email}", step="retry")

        def _auto_sync(file_name: str, email: str, em: "EventEmitter") -> bool:
            cfg = config_snapshot
            if not _is_auto_sync_enabled(cfg):
                return True
            base_url = cfg.get("base_url", "").strip()
            bearer = cfg.get("bearer_token", "").strip()
            if not base_url or not bearer:
                em.error("自动同步配置缺少平台地址或 Token，请先保存配置", step="sync")
                return False

            em.info(f"正在自动同步 {email}...", step="sync")
            fpath = os.path.join(TOKENS_DIR, file_name)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    token_data = json.load(f)
            except Exception as e:
                em.error(f"自动同步异常: 读取本地 Token 失败: {e}", step="sync")
                return False

            last_status = 0
            last_body = ""
            for attempt in range(3):
                try:
                    result = _push_account_api_with_dedupe(
                        base_url=base_url,
                        bearer=bearer,
                        email=email,
                        token_data=token_data,
                        check_before=(attempt == 0),
                        check_after=True,
                    )
                    last_status = int(result.get("status") or 0)
                    last_body = str(result.get("body") or "")
                    if result.get("ok"):
                        if not _mark_token_uploaded_platform(fpath, "sub2api"):
                            em.warn(f"自动同步成功但本地标记失败: {email}", step="sync")
                        reason = str(result.get("reason") or "")
                        if reason == "updated_existing_before_create":
                            em.success(
                                f"自动同步命中已存在账号并更新凭据: {email} (id={result.get('existing_id', '-')})",
                                step="sync",
                            )
                        elif reason == "exists_before_create_update_failed":
                            em.warn(
                                f"自动同步命中已存在账号但更新失败，保持远端现状: {email} "
                                f"(id={result.get('existing_id', '-')}, status={result.get('update_status', '-')}) "
                                f"{str(result.get('update_body') or '')[:120]}",
                                step="sync",
                            )
                        elif result.get("skipped"):
                            em.success(f"自动同步成功: {email}", step="sync")
                        else:
                            em.success(f"自动同步成功: {email}", step="sync")
                        return True
                except Exception as e:
                    last_status = 0
                    last_body = str(e)
                if attempt < 2:
                    time.sleep(2 ** attempt)

            em.error(f"自动同步失败({last_status}): {last_body[:120]}", step="sync")
            return False

        def _upload_to_cpa(file_name: str, file_path: str, token_json: str, email: str, prefix: str) -> bool:
            if not pool_maintainer:
                return True
            try:
                td = json.loads(token_json)
                cpa_ok = pool_maintainer.upload_token(file_name, td, proxy=proxy or "")
                if cpa_ok:
                    if not _mark_token_uploaded_platform(file_path, "cpa"):
                        emitter.warn(f"{prefix}CPA 上传成功但本地标记失败: {email}", step="cpa_upload")
                    emitter.success(f"{prefix}CPA 上传成功: {email}", step="cpa_upload")
                else:
                    emitter.error(f"{prefix}CPA 上传失败: {email}", step="cpa_upload")
                return cpa_ok
            except Exception as ex:
                emitter.error(f"{prefix}CPA 上传异常: {ex}", step="cpa_upload")
                return False

        def _upload_to_sub2api(file_name: str, email: str, refresh_token: str, prefix: str) -> bool:
            if not auto_sync_enabled:
                return True
            if not refresh_token:
                emitter.error(f"{prefix}缺少 refresh_token，无法自动同步: {email}", step="sync")
                return False
            return _auto_sync(file_name, email, emitter)

        def _register_decoupled_token(
            token_key: str,
            email: str,
            prefix: str,
            required_platforms: set[str],
            failed_platforms: set[str],
        ) -> None:
            final_ok: Optional[bool] = None
            no_required_platforms = False
            with token_states_lock:
                token_states[token_key] = {
                    "email": email,
                    "prefix": prefix,
                    "required": set(required_platforms),
                    "done": set(),
                    "failed": set(failed_platforms),
                    "finalized": False,
                }
                state = token_states[token_key]
                if state["failed"]:
                    state["finalized"] = True
                    token_states.pop(token_key, None)
                    final_ok = False
                elif not state["required"]:
                    state["finalized"] = True
                    token_states.pop(token_key, None)
                    no_required_platforms = True
            if final_ok is not None:
                _apply_final_result(email, prefix, final_ok)
                return
            if no_required_platforms:
                # 有限配额耗尽后，后续注册不应继续计入成功。
                if _decoupled_slots_exhausted():
                    emitter.info(
                        f"{prefix}平台目标已满足，跳过本次上传且不计成功: {email}",
                        step="auto_stop",
                    )
                    self.stop_event.set()
                    return
                # 兼容手动启动且无上传平台/无限配额场景：保留“注册成功”计数行为。
                _apply_final_result(email, prefix, True)

        def _complete_decoupled_platform(token_key: str, platform: str, ok: bool) -> None:
            final_ok: Optional[bool] = None
            email = "unknown"
            prefix = ""
            with token_states_lock:
                state = token_states.get(token_key)
                if not state or state.get("finalized"):
                    return
                if ok:
                    state["done"].add(platform)
                else:
                    state["failed"].add(platform)
                email = state.get("email", "unknown")
                prefix = state.get("prefix", "")
                if state["failed"]:
                    state["finalized"] = True
                    token_states.pop(token_key, None)
                    final_ok = False
                elif state["required"].issubset(state["done"]):
                    state["finalized"] = True
                    token_states.pop(token_key, None)
                    final_ok = True
            if final_ok is not None:
                _apply_final_result(email, prefix, final_ok)

        def _enqueue_upload_job(platform: str, job: Dict[str, Any], prefix: str) -> None:
            q = upload_queues.get(platform)
            if not q:
                _release_upload_slot(platform)
                _complete_decoupled_platform(job["token_key"], platform, False)
                return
            try:
                q.put_nowait(job)
                _refresh_backlog()
            except queue.Full:
                emitter.error(f"{prefix}{platform.upper()} 上传队列已满，跳过: {job.get('email', 'unknown')}", step="sync")
                _release_upload_slot(platform)
                _complete_decoupled_platform(job["token_key"], platform, False)

        def _upload_worker_loop(platform: str) -> None:
            q = upload_queues[platform]
            while True:
                if producers_done.is_set() and q.empty():
                    break
                try:
                    job = q.get(timeout=0.3)
                except queue.Empty:
                    _refresh_backlog()
                    continue

                _refresh_backlog()
                ok = False
                if platform == "cpa":
                    ok = _upload_to_cpa(
                        file_name=job["file_name"],
                        file_path=job["file_path"],
                        token_json=job["token_json"],
                        email=job["email"],
                        prefix=job.get("prefix", ""),
                    )
                elif platform == "sub2api":
                    ok = _upload_to_sub2api(
                        file_name=job["file_name"],
                        email=job["email"],
                        refresh_token=job.get("refresh_token", ""),
                        prefix=job.get("prefix", ""),
                    )
                _record_platform_result(platform, ok)
                if not ok:
                    _release_upload_slot(platform)
                _complete_decoupled_platform(job["token_key"], platform, ok)
                q.task_done()
                _refresh_backlog()

        def _worker_loop(worker_id: int) -> None:
            worker_label = f"W{worker_id}"
            prefix = f"[{worker_label}] " if n > 1 else ""
            worker_emitter = emitter.bind(worker_id=worker_id, worker_label=worker_label)
            count = 0
            while not self.stop_event.is_set():
                if _decoupled_slots_exhausted():
                    worker_emitter.info(f"{prefix}双平台目标已满足，停止新增注册", step="auto_stop")
                    self.stop_event.set()
                    break
                count += 1
                provider_name, provider = mail_router.next_provider()
                attempt_emitter = worker_emitter.bind(mail_provider=provider_name)
                attempt_emitter.info(
                    f"{prefix}>>> 第 {count} 次注册 (邮箱: {provider_name}) <<<",
                    step="start",
                    attempt=count,
                )
                try:
                    run_func = _get_run_function()
                    token_json = run_func(
                        proxy=proxy or None,
                        emitter=attempt_emitter,
                        stop_event=self.stop_event,
                        mail_provider=provider,
                        proxy_pool_config={
                            "enabled": bool(config_snapshot.get("proxy_pool_enabled", False)),
                            "api_url": str(config_snapshot.get("proxy_pool_api_url", "")).strip(),
                            "auth_mode": str(config_snapshot.get("proxy_pool_auth_mode", "query")).strip().lower(),
                            "api_key": str(config_snapshot.get("proxy_pool_api_key", "")).strip(),
                            "count": config_snapshot.get("proxy_pool_count", 1),
                            "country": str(config_snapshot.get("proxy_pool_country", "US") or "US").strip().upper(),
                        },
                    )

                    if self.stop_event.is_set() and not token_json:
                        break

                    if token_json:
                        mail_router.report_success(provider_name)
                        try:
                            t_data = json.loads(token_json)
                            fname_email = t_data.get("email", "unknown").replace("@", "_")
                            refresh_token = str(t_data.get("refresh_token", "") or "").strip()
                            email = str(t_data.get("email", "unknown") or "unknown").strip()
                        except Exception:
                            fname_email = "unknown"
                            refresh_token = ""
                            email = "unknown"

                        if not _register_runtime_identity(email, refresh_token):
                            attempt_emitter.warn(
                                f"{prefix}检测到重复账号（同邮箱/refresh_token），已跳过: {email}",
                                step="dedupe",
                                account_email=email,
                            )
                            continue

                        file_name = f"token_{fname_email}_{time.time_ns()}.json"
                        file_path = os.path.join(TOKENS_DIR, file_name)
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(token_json)

                        attempt_emitter.success(f"{prefix}Token 已保存: {file_name}", step="saved", account_email=email)
                        self.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "token_saved",
                            "message": file_name,
                            "step": "saved",
                            "worker_id": worker_id,
                            "worker_label": worker_label,
                            "mail_provider": provider_name,
                            "attempt": count,
                            "account_email": email,
                        })

                        if upload_mode == "snapshot":
                            if snapshot_strict_serial:
                                selected_platform = _reserve_snapshot_serial_platform()
                                if selected_platform == "cpa":
                                    attempt_emitter.info(f"{prefix}串行模式：本次仅上传 CPA -> {email}", step="cpa_upload", account_email=email)
                                    cpa_ok = _upload_to_cpa(file_name, file_path, token_json, email, prefix) if pool_maintainer else True
                                    _record_platform_result("cpa", cpa_ok)
                                    if not cpa_ok:
                                        _release_upload_slot("cpa")
                                    _apply_final_result(email, prefix, cpa_ok)
                                elif selected_platform == "sub2api":
                                    attempt_emitter.info(f"{prefix}串行模式：本次仅上传 Sub2Api -> {email}", step="sync", account_email=email)
                                    sub2api_ok = _upload_to_sub2api(file_name, email, refresh_token, prefix) if auto_sync_enabled else True
                                    _record_platform_result("sub2api", sub2api_ok)
                                    if not sub2api_ok:
                                        _release_upload_slot("sub2api")
                                    _apply_final_result(email, prefix, sub2api_ok)
                                else:
                                    attempt_emitter.info(f"{prefix}串行模式目标已满足，停止新增上传: {email}", step="auto_stop", account_email=email)
                                    self.stop_event.set()
                            else:
                                cpa_ok = True
                                cpa_required = False
                                if pool_maintainer:
                                    cpa_required = _reserve_upload_slot("cpa")
                                if pool_maintainer and not cpa_required:
                                    attempt_emitter.info(f"{prefix}CPA 已达目标阈值，跳过上传: {email}", step="cpa_upload", account_email=email)
                                if pool_maintainer and cpa_required:
                                    cpa_ok = _upload_to_cpa(file_name, file_path, token_json, email, prefix)
                                    _record_platform_result("cpa", cpa_ok)
                                    if not cpa_ok:
                                        _release_upload_slot("cpa")

                                sub2api_ok = True
                                sub2api_required = False
                                if auto_sync_enabled:
                                    sub2api_required = _reserve_upload_slot("sub2api")
                                if auto_sync_enabled and not sub2api_required:
                                    attempt_emitter.info(f"{prefix}Sub2Api 已达目标阈值，跳过同步: {email}", step="sync", account_email=email)
                                if auto_sync_enabled and sub2api_required:
                                    sub2api_ok = _upload_to_sub2api(file_name, email, refresh_token, prefix)
                                    _record_platform_result("sub2api", sub2api_ok)
                                    if not sub2api_ok:
                                        _release_upload_slot("sub2api")

                                _apply_final_result(email, prefix, cpa_ok and sub2api_ok)
                        else:
                            required_platforms: set[str] = set()
                            failed_platforms: set[str] = set()

                            if pool_maintainer:
                                if _reserve_upload_slot("cpa"):
                                    required_platforms.add("cpa")
                                else:
                                    attempt_emitter.info(f"{prefix}CPA 已达目标阈值，跳过上传: {email}", step="cpa_upload", account_email=email)

                            if auto_sync_enabled:
                                if _reserve_upload_slot("sub2api"):
                                    if refresh_token:
                                        required_platforms.add("sub2api")
                                    else:
                                        failed_platforms.add("sub2api")
                                        _release_upload_slot("sub2api")
                                        attempt_emitter.error(f"{prefix}缺少 refresh_token，无法自动同步: {email}", step="sync", account_email=email)
                                else:
                                    attempt_emitter.info(f"{prefix}Sub2Api 已达目标阈值，跳过同步: {email}", step="sync", account_email=email)

                            token_key = file_name
                            _register_decoupled_token(token_key, email, prefix, required_platforms, failed_platforms)

                            base_job = {
                                "token_key": token_key,
                                "file_name": file_name,
                                "file_path": file_path,
                                "token_json": token_json,
                                "email": email,
                                "refresh_token": refresh_token,
                                "prefix": prefix,
                            }
                            if "cpa" in required_platforms:
                                _enqueue_upload_job("cpa", base_job, prefix)
                            if "sub2api" in required_platforms:
                                _enqueue_upload_job("sub2api", base_job, prefix)
                    else:
                        mail_router.report_failure(provider_name)
                        with self._task_lock:
                            self.fail_count += 1
                            self.run_fail_count += 1
                            self.last_error = f"注册失败: worker={worker_id}"
                            _save_state(self.success_count, self.fail_count)
                            self.status = "running"
                        attempt_emitter.error(f"{prefix}本次注册失败，稍后重试...", step="retry")

                except Exception as e:
                    mail_router.report_failure(provider_name)
                    with self._task_lock:
                        self.fail_count += 1
                        self.run_fail_count += 1
                        self.last_error = str(e)
                        _save_state(self.success_count, self.fail_count)
                    attempt_emitter.error(f"{prefix}发生未捕获异常: {e}", step="runtime")

                if self.stop_event.is_set():
                    break

                wait = random.randint(5, 30)
                attempt_emitter.info(f"{prefix}休息 {wait} 秒后继续...", step="wait")
                self.stop_event.wait(wait)

        if upload_mode == "decoupled":
            upload_queues = {
                platform: queue.Queue(maxsize=2000)
                for platform in UPLOAD_PLATFORMS
            }
            with self._task_lock:
                self._upload_queues = upload_queues
            _refresh_backlog()
            for platform in UPLOAD_PLATFORMS:
                t = threading.Thread(target=_upload_worker_loop, args=(platform,), daemon=True)
                upload_workers[platform] = t
                t.start()

        def _monitor() -> None:
            with self._task_lock:
                workers = list(self._worker_threads.values())
            for t in workers:
                t.join()
            if upload_mode == "decoupled":
                producers_done.set()
                for ut in upload_workers.values():
                    ut.join()
                stale_results: List[Dict[str, Any]] = []
                with token_states_lock:
                    for token_key in list(token_states.keys()):
                        state = token_states.pop(token_key, None)
                        if state and not state.get("finalized"):
                            stale_results.append(state)
                for state in stale_results:
                    _apply_final_result(state.get("email", "unknown"), state.get("prefix", ""), False)
                with self._task_lock:
                    self._upload_queues = {}
                    self.platform_backlog_count = {name: 0 for name in UPLOAD_PLATFORMS}
                    self._emit_event_locked("stats.updated", {"stats": self._stats_snapshot_locked()}, bump_revision=True)

            emitter.info("所有Worker已停止", step="stopped")
            self._stop_bridge()
            with self._task_lock:
                self._worker_threads.clear()
                self.worker_count = 0
                self.finished_at = self._now_iso()
                if self.status == "stopping":
                    self.status = "stopped"
                    self.stop_reason = self.stop_reason or "manual_stop"
                elif self.status == "failed":
                    pass
                elif self.run_fail_count > 0 and self.run_success_count == 0:
                    self.status = "failed"
                    self.stop_reason = self.stop_reason or "run_failed"
                else:
                    self.status = "finished"
                if self.status == "stopped":
                    self._finalize_worker_runtimes_locked("stopped")
                self._sync_status_from_workers_locked()
                self._emit_event_locked("task.finished", {"task": self._task_snapshot_locked()}, bump_revision=True)
                self._emit_event_locked("snapshot", {"snapshot": self._status_snapshot_locked()})

        for wid in range(1, n + 1):
            t = threading.Thread(target=_worker_loop, args=(wid,), daemon=True)
            with self._task_lock:
                self._worker_threads[wid] = t
            t.start()

        with self._task_lock:
            self.status = "running"
            self._emit_event_locked("task.updated", {"task": self._task_snapshot_locked()}, bump_revision=True)
            self._emit_event_locked("snapshot", {"snapshot": self._status_snapshot_locked()})

        self.thread = threading.Thread(target=_monitor, daemon=True)
        self.thread.start()

    def stop_task(self) -> None:
        with self._task_lock:
            if self.status in {"starting", "running", "failed"}:
                self.status = "stopping"
                self.stop_reason = "manual_stop"
                self.stop_event.set()
                self._emit_event_locked("task.updated", {"task": self._task_snapshot_locked()}, bump_revision=True)
                self._emit_event_locked("snapshot", {"snapshot": self._status_snapshot_locked()})
            else:
                return
        self.broadcast({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": "收到停止请求，等待当前注册流程收尾...",
            "step": "stopping",
        })


_state = TaskState()


def request_service_shutdown() -> None:
    """供外部启动器调用，通知服务进入收尾停止流程。"""
    _service_shutdown_event.set()

    try:
        _state.broadcast({
            "level": "info",
            "message": "收到服务关闭请求，正在停止任务与后台维护线程...",
            "step": "shutdown",
        })
    except Exception:
        pass

    try:
        _state.stop_task()
    except Exception:
        pass

    try:
        _stop_auto_maintain()
    except Exception:
        pass

    try:
        _stop_sub2api_auto_maintain()
    except Exception:
        pass


# 自动维护后台任务
_auto_maintain_thread: Optional[threading.Thread] = None
_auto_maintain_stop: Optional[threading.Event] = None
_auto_maintain_ctl_lock = threading.Lock()
_pool_maintain_lock = threading.Lock()


def _get_pool_maintainer(cfg: Optional[Dict[str, Any]] = None) -> Optional[PoolMaintainer]:
    cfg = cfg or _get_sync_config()
    base_url = str(cfg.get("cpa_base_url", "")).strip()
    token = str(cfg.get("cpa_token", "")).strip()
    if not base_url or not token:
        return None
    return PoolMaintainer(
        cpa_base_url=base_url,
        cpa_token=token,
        min_candidates=int(cfg.get("min_candidates", 800)),
        used_percent_threshold=int(cfg.get("used_percent_threshold", 95)),
    )


def _get_sub2api_maintainer(cfg: Optional[Dict[str, Any]] = None) -> Optional[Sub2ApiMaintainer]:
    cfg = cfg or _get_sync_config()
    base_url = str(cfg.get("base_url", "")).strip()
    bearer = str(cfg.get("bearer_token", "")).strip()
    email = str(cfg.get("email", "")).strip()
    password = str(cfg.get("password", "")).strip()
    if not base_url:
        return None
    if not bearer and not (email and password):
        return None
    return Sub2ApiMaintainer(
        base_url=base_url,
        bearer_token=bearer,
        min_candidates=int(cfg.get("sub2api_min_candidates", 200)),
        email=email,
        password=password,
    )


# ==========================================
# API 路由
# ==========================================


class StartRequest(BaseModel):
    proxy: str = ""
    worker_count: int = 1
    target_count: int = 0


class ProxyCheckRequest(BaseModel):
    proxy: str = ""


class ProxyPoolTestRequest(BaseModel):
    enabled: bool = True
    api_url: str = "https://zenproxy.top/api/fetch"
    auth_mode: str = "query"  # "header" | "query"
    api_key: str = ""
    count: int = 1
    country: str = "US"


class ProxyPoolConfigRequest(BaseModel):
    proxy_pool_enabled: bool = True
    proxy_pool_api_url: str = "https://zenproxy.top/api/fetch"
    proxy_pool_auth_mode: str = "query"  # "header" | "query"
    proxy_pool_api_key: str = ""
    proxy_pool_count: int = 1
    proxy_pool_country: str = "US"


class ProxySaveRequest(BaseModel):
    proxy: str = ""
    auto_register: bool = False


class SyncConfigRequest(BaseModel):
    base_url: str          # Sub2Api 平台地址
    bearer_token: str = ""  # 管理员 JWT（可选）
    email: str = ""        # 管理员邮箱
    password: str = ""     # 管理员密码
    account_name: str = "AutoReg"
    auto_sync: bool = True
    upload_mode: str = "snapshot"  # "snapshot" | "decoupled"
    sub2api_min_candidates: int = 200
    sub2api_auto_maintain: bool = False
    sub2api_maintain_interval_minutes: int = 30
    sub2api_maintain_actions: Dict[str, bool] = Field(default_factory=dict)
    multithread: bool = False
    thread_count: int = 3
    auto_register: bool = False


class SyncNowRequest(BaseModel):
    filenames: List[str] = []  # 空列表 = 同步全部


class UploadModeRequest(BaseModel):
    upload_mode: str = "snapshot"  # "snapshot" | "decoupled"


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html_path = STATIC_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>前端文件未找到</h1>", status_code=404)


@app.post("/api/start")
async def api_start(req: StartRequest) -> Dict[str, Any]:
    try:
        _state.start_task(req.proxy, req.worker_count, target_count=req.target_count)
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    snapshot = _state.get_status_snapshot()
    return {
        "run_id": snapshot["task"].get("run_id"),
        "task": snapshot["task"],
        "runtime": snapshot["runtime"],
        "stats": snapshot["stats"],
        "server_time": snapshot["server_time"],
    }


@app.post("/api/stop")
async def api_stop() -> Dict[str, Any]:
    if _state.status in {"stopped", "finished", "failed"} and not _state.run_id:
        raise HTTPException(status_code=409, detail="没有正在运行的任务")
    _state.stop_task()
    return _state.get_status_snapshot()


@app.post("/api/proxy/save")
async def api_save_proxy(req: ProxySaveRequest) -> Dict[str, str]:
    cfg = _get_sync_config()
    cfg["proxy"] = req.proxy.strip()
    cfg["auto_register"] = req.auto_register
    _save_sync_config(cfg)
    return {"status": "saved"}


class TaskControlRequest(BaseModel):
    multithread: Optional[bool] = None
    thread_count: Optional[int] = None
    auto_register: Optional[bool] = None


@app.post("/api/task-control")
async def api_save_task_control(req: TaskControlRequest) -> Dict[str, str]:
    cfg = _get_sync_config()
    if req.multithread is not None:
        cfg["multithread"] = req.multithread
    if req.thread_count is not None:
        cfg["thread_count"] = max(1, min(req.thread_count, 10))
    if req.auto_register is not None:
        cfg["auto_register"] = req.auto_register
    _save_sync_config(cfg)
    return {"status": "saved"}


@app.get("/api/proxy")
async def api_get_proxy() -> Dict[str, Any]:
    cfg = _get_sync_config()
    return {
        "proxy": cfg.get("proxy", ""),
        "auto_register": cfg.get("auto_register", False),
    }


@app.get("/api/status")
async def api_status() -> Dict[str, Any]:
    return _state.get_status_snapshot()


@app.get("/api/tokens")
async def api_tokens() -> Dict[str, Any]:
    def _read_tokens():
        tokens = []
        if os.path.isdir(TOKENS_DIR):
            import re
            def _sort_key(f):
                m = re.search(r'_(\d{10,})\.json$', f)
                return int(m.group(1)) if m else 0
            
            all_files = [f for f in os.listdir(TOKENS_DIR) if f.endswith(".json")]
            all_files.sort(key=_sort_key, reverse=True)
            for fname in all_files:
                fpath = os.path.join(TOKENS_DIR, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content_raw = json.load(f)
                    content = content_raw if isinstance(content_raw, dict) else {}
                    uploaded_platforms = _extract_uploaded_platforms(content)
                    tokens.append(
                        {
                            "filename": fname,
                            "email": content.get("email", ""),
                            "expired": content.get("expired", ""),
                            "uploaded_platforms": uploaded_platforms,
                            "content": content,
                        }
                    )
                except Exception:
                    pass
        return tokens
        
    tokens = await run_in_threadpool(_read_tokens)
    return {"tokens": tokens}


@app.delete("/api/tokens/{filename}")
async def api_delete_token(filename: str) -> Dict[str, str]:
    # 安全过滤：防止路径穿越
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="非法文件名")
    fpath = os.path.join(TOKENS_DIR, filename)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="文件不存在")
    os.remove(fpath)
    return {"status": "deleted"}


@app.get("/api/sync-config")
async def api_get_sync_config() -> Dict[str, Any]:
    """获取当前同步配置（脱敏）"""
    cfg = _get_sync_config()
    cfg["password"] = ""  # 不回传密码
    token = cfg.get("bearer_token", "")
    cfg["bearer_token_preview"] = token[:12] + "..." if len(token) > 12 else (token or "")
    cfg["bearer_token"] = ""  # 不回传完整 token
    # 脱敏 cpa_token
    cpa_token = str(cfg.get("cpa_token", ""))
    cfg["cpa_token_preview"] = (cpa_token[:12] + "...") if len(cpa_token) > 12 else (cpa_token or "")
    cfg["cpa_token"] = ""
    proxy_pool_api_key = str(cfg.get("proxy_pool_api_key", ""))
    cfg["proxy_pool_api_key_preview"] = (
        (proxy_pool_api_key[:8] + "...") if len(proxy_pool_api_key) > 8 else (proxy_pool_api_key or "")
    )
    cfg["proxy_pool_api_key"] = ""
    # 脱敏 mail_provider_configs
    raw_configs = cfg.get("mail_provider_configs") or {}
    safe_configs: Dict[str, Dict] = {}
    for pname, pcfg in raw_configs.items():
        if not isinstance(pcfg, dict):
            continue
        sc = dict(pcfg)
        for secret_key in ("bearer_token", "api_key", "admin_password"):
            val = str(sc.get(secret_key, ""))
            if val:
                sc[f"{secret_key}_preview"] = (val[:8] + "...") if len(val) > 8 else val
                sc.pop(secret_key, None)
        safe_configs[pname] = sc
    cfg["mail_provider_configs"] = safe_configs
    cfg.setdefault("sub2api_min_candidates", 200)
    cfg.setdefault("sub2api_auto_maintain", False)
    cfg.setdefault("sub2api_maintain_interval_minutes", 30)
    cfg.setdefault("upload_mode", "snapshot")
    cfg.setdefault("multithread", False)
    cfg.setdefault("thread_count", 3)
    cfg.setdefault("proxy_pool_enabled", True)
    cfg.setdefault("proxy_pool_api_url", "https://zenproxy.top/api/fetch")
    cfg.setdefault("proxy_pool_auth_mode", "query")
    cfg.setdefault("proxy_pool_count", 1)
    cfg.setdefault("proxy_pool_country", "US")
    cfg["auto_sync"] = _is_auto_sync_enabled(cfg)
    return cfg


@app.get("/api/proxy-pool/config")
async def api_get_proxy_pool_config() -> Dict[str, Any]:
    cfg = _get_sync_config()
    api_url = str(cfg.get("proxy_pool_api_url", "https://zenproxy.top/api/fetch") or "").strip()
    if not api_url:
        api_url = "https://zenproxy.top/api/fetch"
    auth_mode = str(cfg.get("proxy_pool_auth_mode", "query") or "").strip().lower()
    if auth_mode not in ("header", "query"):
        auth_mode = "query"
    try:
        count = max(1, min(int(cfg.get("proxy_pool_count", 1) or 1), 20))
    except (TypeError, ValueError):
        count = 1
    country = str(cfg.get("proxy_pool_country", "US") or "US").strip().upper() or "US"
    api_key = str(cfg.get("proxy_pool_api_key", "") or "").strip()
    return {
        "proxy_pool_enabled": bool(cfg.get("proxy_pool_enabled", True)),
        "proxy_pool_api_url": api_url,
        "proxy_pool_auth_mode": auth_mode,
        "proxy_pool_api_key": "",
        "proxy_pool_api_key_preview": (api_key[:8] + "...") if len(api_key) > 8 else (api_key or ""),
        "proxy_pool_count": count,
        "proxy_pool_country": country,
    }


@app.post("/api/proxy-pool/config")
async def api_set_proxy_pool_config(req: ProxyPoolConfigRequest) -> Dict[str, Any]:
    cfg = _get_sync_config()
    proxy_pool_auth_mode = str(req.proxy_pool_auth_mode or "query").strip().lower()
    if proxy_pool_auth_mode not in ("header", "query"):
        proxy_pool_auth_mode = "query"

    proxy_pool_api_url = str(req.proxy_pool_api_url or "https://zenproxy.top/api/fetch").strip()
    if not proxy_pool_api_url:
        proxy_pool_api_url = "https://zenproxy.top/api/fetch"

    proxy_pool_api_key = req.proxy_pool_api_key.strip() if req.proxy_pool_api_key else ""
    if not proxy_pool_api_key:
        proxy_pool_api_key = str(cfg.get("proxy_pool_api_key", "") or "").strip()

    try:
        proxy_pool_count = max(1, min(int(req.proxy_pool_count), 20))
    except (TypeError, ValueError):
        proxy_pool_count = 1
    proxy_pool_country = str(req.proxy_pool_country or "US").strip().upper() or "US"

    cfg.update({
        "proxy_pool_enabled": bool(req.proxy_pool_enabled),
        "proxy_pool_api_url": proxy_pool_api_url,
        "proxy_pool_auth_mode": proxy_pool_auth_mode,
        "proxy_pool_api_key": proxy_pool_api_key,
        "proxy_pool_count": proxy_pool_count,
        "proxy_pool_country": proxy_pool_country,
    })
    _save_sync_config(cfg)
    return {"status": "saved"}


@app.post("/api/upload-mode")
async def api_set_upload_mode(req: UploadModeRequest) -> Dict[str, Any]:
    upload_mode = str(req.upload_mode or "snapshot").strip().lower()
    if upload_mode not in ("snapshot", "decoupled"):
        raise HTTPException(status_code=400, detail="upload_mode 仅支持 snapshot / decoupled")
    cfg = _get_sync_config()
    cfg["upload_mode"] = upload_mode
    _save_sync_config(cfg)
    # 空闲状态下同步到内存状态，便于前端立即看到当前策略
    with _state._task_lock:
        if _state.status == "idle":
            _state.upload_mode = upload_mode
    return {"status": "saved", "upload_mode": upload_mode}


def _verify_sub2api_login(base_url: str, email: str, password: str) -> Dict[str, Any]:
    """通过 HTTP API 验证 Sub2Api 平台登录凭据是否正确"""
    from curl_cffi import requests as cffi_req

    # 自动补全协议（优先 https://）
    url = base_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    login_url = url.rstrip("/") + "/api/v1/auth/login"
    try:
        resp = cffi_req.post(
            login_url,
            json={"email": email, "password": password},
            impersonate="chrome",
            timeout=15,
        )
        raw_body = resp.text
        if resp.status_code != 200:
            try:
                err_body = json.loads(raw_body)
                err_msg = err_body.get("message") or err_body.get("error") or raw_body[:200]
            except json.JSONDecodeError:
                err_msg = raw_body[:200]
            return {"ok": False, "error": f"登录失败(HTTP {resp.status_code}): {err_msg}"}
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            return {"ok": False, "error": f"服务器返回非 JSON 格式: {raw_body[:200]}"}

        token = (
            body.get("token")
            or body.get("access_token")
            or (body.get("data") or {}).get("token")
            or (body.get("data") or {}).get("access_token")
            or ""
        )
        return {"ok": True, "token": token}
    except Exception as e:
        return {"ok": False, "error": f"请求异常: {e}"}


def _verify_sub2api_token(base_url: str, bearer_token: str) -> Dict[str, Any]:
    from curl_cffi import requests as cffi_req

    url = base_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    verify_url = url.rstrip("/") + "/api/v1/admin/dashboard/stats"
    try:
        resp = cffi_req.get(
            verify_url,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Accept": "application/json",
            },
            params={"timezone": "Asia/Shanghai"},
            impersonate="chrome",
            timeout=15,
        )
        if resp.status_code != 200:
            return {"ok": False, "error": f"Bearer Token 验证失败: HTTP {resp.status_code}"}
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": f"Bearer Token 验证异常: {e}"}


@app.post("/api/sync-config")
async def api_set_sync_config(req: SyncConfigRequest) -> Dict[str, Any]:
    """保存同步配置（先验证登录凭据）"""
    cfg = _get_sync_config()
    new_base_url = req.base_url.strip()
    if new_base_url and not new_base_url.startswith(("http://", "https://")):
        new_base_url = "https://" + new_base_url
    new_email = req.email.strip() or str(cfg.get("email", "") or "").strip()
    new_password = req.password.strip() if req.password else str(cfg.get("password", "") or "").strip()
    bearer_token = req.bearer_token.strip() or str(cfg.get("bearer_token", "") or "").strip()

    if not new_base_url:
        raise HTTPException(status_code=400, detail="请填写平台地址")

    verified_token = bearer_token
    if new_email and new_password:
        verify = await run_in_threadpool(_verify_sub2api_login, new_base_url, new_email, new_password)
        if not verify["ok"]:
            raise HTTPException(status_code=400, detail=verify["error"])
        verified_token = str(verify.get("token") or "").strip() or bearer_token
    elif bearer_token:
        verify = await run_in_threadpool(_verify_sub2api_token, new_base_url, bearer_token)
        if not verify["ok"]:
            raise HTTPException(status_code=400, detail=verify["error"])
    else:
        raise HTTPException(status_code=400, detail="请填写 Bearer Token 或邮箱和密码")

    upload_mode = str(req.upload_mode or "snapshot").strip().lower()
    if upload_mode not in ("snapshot", "decoupled"):
        upload_mode = "snapshot"

    cfg.update({
        "base_url": new_base_url,
        "bearer_token": verified_token,
        "email": new_email,
        "password": new_password,
        "account_name": req.account_name.strip(),
        "auto_sync": req.auto_sync,
        "upload_mode": upload_mode,
        "sub2api_min_candidates": max(1, req.sub2api_min_candidates),
        "sub2api_auto_maintain": req.sub2api_auto_maintain,
        "sub2api_maintain_interval_minutes": max(5, req.sub2api_maintain_interval_minutes),
        "sub2api_maintain_actions": _normalize_sub2api_maintain_actions(req.sub2api_maintain_actions),
        "multithread": req.multithread,
        "thread_count": max(1, min(req.thread_count, 10)),
        "auto_register": req.auto_register,
    })
    # 清理历史遗留字段
    cfg.pop("headful", None)
    _save_sync_config(cfg)
    _clear_sub2api_accounts_cache()

    # 先停再启，确保旧线程已退出
    _stop_sub2api_auto_maintain()
    if req.sub2api_auto_maintain:
        _start_sub2api_auto_maintain()

    return {"status": "saved", "verified": True}


@app.post("/api/sync-now")
async def api_sync_now(req: SyncNowRequest) -> Dict[str, Any]:
    """手动触发同步：将本地 Token 文件完整导入 Sub2Api 平台"""
    def _sync_now() -> Dict[str, Any]:
        cfg = _get_sync_config()
        base_url = str(cfg.get("base_url", "") or "").strip()
        bearer = str(cfg.get("bearer_token", "") or "").strip()
        if not base_url or not bearer:
            raise HTTPException(status_code=400, detail="请先配置 Sub2Api 平台地址和 Bearer Token")

        results = []
        fnames = list(req.filenames or [])
        if not fnames and os.path.isdir(TOKENS_DIR):
            fnames = [f for f in os.listdir(TOKENS_DIR) if f.endswith(".json")]

        for fname in fnames:
            if "/" in fname or "\\" in fname or ".." in fname:
                continue
            fpath = os.path.join(TOKENS_DIR, fname)
            if not os.path.isfile(fpath):
                results.append({"file": fname, "ok": False, "error": "文件不存在"})
                continue
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                email = data.get("email", fname)
                result = _push_account_api_with_dedupe(
                    base_url=base_url,
                    bearer=bearer,
                    email=str(email),
                    token_data=data,
                    check_before=True,
                    check_after=True,
                )
                if result["ok"]:
                    _mark_token_uploaded_platform(fpath, "sub2api")
                results.append({
                    "file": fname,
                    "email": email,
                    "ok": result["ok"],
                    "status": result["status"],
                    "body": str(result["body"] or "")[:200],
                })
            except Exception as e:
                results.append({"file": fname, "ok": False, "error": str(e)})

        ok_count = sum(1 for r in results if r["ok"])
        fail_count = len(results) - ok_count
        return {"total": len(results), "ok": ok_count, "fail": fail_count, "results": results}

    return await run_in_threadpool(_sync_now)


class Sub2ApiLoginRequest(BaseModel):
    base_url: str
    email: str
    password: str


@app.post("/api/sub2api-login")
async def api_sub2api_login(req: Sub2ApiLoginRequest) -> Dict[str, Any]:
    """用账号密码登录 Sub2Api 平台，自动获取并保存 Bearer Token"""
    def _login() -> Dict[str, Any]:
        cfg = _get_sync_config()
        base_url = req.base_url.strip()
        if not base_url:
            raise HTTPException(status_code=400, detail="请填写平台地址")
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url

        login_url = base_url.rstrip("/") + "/api/v1/auth/login"
        payload = json.dumps({"email": req.email, "password": req.password}).encode("utf-8")
        request = urllib.request.Request(
            login_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                raw_body = resp.read().decode("utf-8")
                try:
                    body = json.loads(raw_body)
                except json.JSONDecodeError:
                    raise HTTPException(status_code=502, detail=f"服务器返回非 JSON 格式: {raw_body[:200]}")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                err_body = json.loads(raw)
                err_msg = err_body.get("message") or err_body.get("error") or raw[:200]
            except json.JSONDecodeError:
                err_msg = raw[:200]
            raise HTTPException(status_code=exc.code, detail=f"登录失败: {err_msg}")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"请求异常: {e}")

        token = (
            body.get("token")
            or body.get("access_token")
            or (body.get("data") or {}).get("token")
            or (body.get("data") or {}).get("access_token")
            or ""
        )
        if not token:
            raise HTTPException(status_code=502, detail=f"响应中未找到 token 字段: {str(body)[:300]}")

        cfg["base_url"] = base_url
        cfg["bearer_token"] = token
        _save_sync_config(cfg)
        return {"ok": True, "token_preview": token[:16] + "..."}

    return await run_in_threadpool(_login)


@app.post("/api/check-proxy")
async def api_check_proxy(req: ProxyCheckRequest) -> Dict[str, Any]:
    """检测代理是否可用（通过 Cloudflare Trace）"""
    def _check() -> Dict[str, Any]:
        proxy = req.proxy.strip()
        try:
            from curl_cffi import requests as cffi_req
            import re

            proxies = {"http": proxy, "https": proxy} if proxy else None
            try:
                resp = cffi_req.get(
                    "https://cloudflare.com/cdn-cgi/trace",
                    proxies=proxies,
                    http_version="v2",
                    impersonate="chrome",
                    timeout=8,
                )
            except Exception as exc:
                if "HTTP/3 is not supported over an HTTP proxy" not in str(exc):
                    raise
                resp = cffi_req.get(
                    "https://cloudflare.com/cdn-cgi/trace",
                    proxies=proxies,
                    http_version="v1",
                    impersonate="chrome",
                    timeout=8,
                )
            text = resp.text
            loc_m = re.search(r"^loc=(.+)$", text, re.MULTILINE)
            loc = loc_m.group(1) if loc_m else "?"
            supported = loc not in ("CN", "HK")
            return {"ok": supported, "loc": loc, "error": None if supported else "所在地不支持"}
        except Exception as e:
            return {"ok": False, "loc": None, "error": str(e)}

    return await run_in_threadpool(_check)


@app.post("/api/proxy-pool/test")
async def api_proxy_pool_test(req: ProxyPoolTestRequest) -> Dict[str, Any]:
    """测试代理池取号：返回取到的代理与可选 loc 探测结果"""
    def _test() -> Dict[str, Any]:
        cfg_snapshot = _get_sync_config()
        auth_mode = str(req.auth_mode or "query").strip().lower()
        if auth_mode not in ("header", "query"):
            auth_mode = "query"
        api_url = str(req.api_url or "https://zenproxy.top/api/fetch").strip() or "https://zenproxy.top/api/fetch"
        api_key = req.api_key.strip() if req.api_key else str(cfg_snapshot.get("proxy_pool_api_key", "")).strip()
        try:
            count = max(1, min(int(req.count or cfg_snapshot.get("proxy_pool_count", 1)), 20))
        except (TypeError, ValueError):
            count = 1
        country = str(req.country or cfg_snapshot.get("proxy_pool_country", "US") or "US").strip().upper() or "US"

        cfg = {
            "enabled": bool(req.enabled),
            "api_url": api_url,
            "auth_mode": auth_mode,
            "api_key": api_key,
            "count": count,
            "country": country,
            "timeout_seconds": 10,
        }
        if not cfg["enabled"]:
            return {"ok": False, "error": "代理池未启用"}
        if not cfg["api_key"]:
            return {"ok": False, "error": "API Key 为空"}

        try:
            from curl_cffi import requests as cffi_req
            import re

            relay_url = _pool_relay_url_from_fetch_url(api_url)
            if relay_url:
                relay_params = {"api_key": api_key, "url": "https://cloudflare.com/cdn-cgi/trace", "country": country}
                try:
                    relay_resp = cffi_req.get(relay_url, params=relay_params, http_version="v2", impersonate="chrome", timeout=8)
                except Exception as exc:
                    if "HTTP/3 is not supported over an HTTP proxy" not in str(exc):
                        raise
                    relay_resp = cffi_req.get(relay_url, params=relay_params, http_version="v1", impersonate="chrome", timeout=8)
                if relay_resp.status_code == 200:
                    relay_text = relay_resp.text
                    relay_loc_m = re.search(r"^loc=(.+)$", relay_text, re.MULTILINE)
                    relay_loc = relay_loc_m.group(1) if relay_loc_m else "?"
                    relay_supported = relay_loc not in ("CN", "HK")
                    return {
                        "ok": True,
                        "proxy": "(relay)",
                        "relay_used": True,
                        "relay_url": relay_url,
                        "count": count,
                        "country": country,
                        "loc": relay_loc,
                        "supported": relay_supported,
                        "trace_error": None,
                    }

            proxy = _fetch_proxy_from_pool(cfg)
            proxies = {"http": proxy, "https": proxy} if proxy else None
            trace_error = ""
            loc = None
            supported = None
            try:
                try:
                    resp = cffi_req.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, http_version="v2", impersonate="chrome", timeout=8)
                except Exception as exc:
                    if "HTTP/3 is not supported over an HTTP proxy" not in str(exc):
                        raise
                    resp = cffi_req.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, http_version="v1", impersonate="chrome", timeout=8)
                text = resp.text
                loc_m = re.search(r"^loc=(.+)$", text, re.MULTILINE)
                loc = loc_m.group(1) if loc_m else "?"
                supported = loc not in ("CN", "HK")
            except Exception as e:
                trace_error = str(e)

            return {
                "ok": True,
                "proxy": proxy,
                "relay_used": False,
                "count": count,
                "country": country,
                "loc": loc,
                "supported": supported,
                "trace_error": trace_error or None,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    return await run_in_threadpool(_test)


@app.get("/api/logs")
async def api_logs(request: Request) -> StreamingResponse:
    """SSE 实时结构化事件流"""

    async def event_generator() -> AsyncGenerator[str, None]:
        q = _state.subscribe()
        last_heartbeat = time.monotonic()
        try:
            snapshot = _state.get_status_snapshot()
            connected = {
                "type": "connected",
                "message": "日志连接成功",
                "run_id": snapshot["task"].get("run_id"),
                "revision": snapshot["task"].get("revision", 0),
                "snapshot": snapshot,
            }
            yield f"event: connected\ndata: {json.dumps(connected, ensure_ascii=False)}\n\n"
            while True:
                if _service_shutdown_event.is_set():
                    break
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=1.0)
                    event_type = str(event.get("type") or "message")
                    yield f"event: {event_type}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                    if _service_shutdown_event.is_set() or str(event.get("step") or "").strip().lower() == "shutdown":
                        break
                except asyncio.TimeoutError:
                    if _service_shutdown_event.is_set():
                        break
                    now = time.monotonic()
                    if now - last_heartbeat >= 15:
                        last_heartbeat = now
                        heartbeat = {
                            "type": "heartbeat",
                            "run_id": _state.run_id,
                            "revision": _state.revision,
                            "server_time": datetime.now().isoformat(timespec="seconds"),
                        }
                        yield f"event: heartbeat\ndata: {json.dumps(heartbeat, ensure_ascii=False)}\n\n"
                except asyncio.CancelledError:
                    break
                except Exception:
                    break
        finally:
            _state.unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )



class BatchSyncRequest(BaseModel):
    filenames: List[str] = []  # 空列表 = 同步全部


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    """解析 JWT payload（不验签）"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        pad = 4 - len(payload) % 4
        if pad != 4:
            payload += "=" * pad
        import base64 as _b64
        decoded = _b64.urlsafe_b64decode(payload.encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _build_account_payload(email: str, token_data: Dict[str, Any]) -> Dict[str, Any]:
    """参考 chatgpt_register.py 构建 /api/v1/admin/accounts 所需 payload"""
    access_token  = token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    id_token      = token_data.get("id_token", "")

    at_payload = _decode_jwt_payload(access_token) if access_token else {}
    at_auth    = at_payload.get("https://api.openai.com/auth") or {}
    chatgpt_account_id = at_auth.get("chatgpt_account_id", "") or token_data.get("account_id", "")
    chatgpt_user_id    = at_auth.get("chatgpt_user_id", "")
    exp_timestamp      = at_payload.get("exp", 0)
    expires_at = exp_timestamp if isinstance(exp_timestamp, int) and exp_timestamp > 0 else int(time.time()) + 863999

    it_payload = _decode_jwt_payload(id_token) if id_token else {}
    it_auth    = it_payload.get("https://api.openai.com/auth") or {}
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


def _push_account_api(base_url: str, bearer: str, email: str, token_data: Dict[str, Any]) -> Dict[str, Any]:
    """调用 /api/v1/admin/accounts 提交完整账号信息"""
    from curl_cffi import requests as cffi_req
    url = base_url.rstrip("/") + "/api/v1/admin/accounts"
    payload = _build_account_payload(email, token_data)
    try:
        resp = cffi_req.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Referer": base_url.rstrip("/") + "/admin/accounts",
            },
            impersonate="chrome",
            timeout=20,
        )
        return {"ok": resp.status_code in (200, 201), "status": resp.status_code, "body": resp.text[:300]}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)}


def _update_sub2api_account_api(
    base_url: str,
    bearer: str,
    account_id: int,
    email: str,
    token_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    命中已存在账号后，更新其凭据，避免“存在即跳过”导致账号长期不刷新。
    """
    from curl_cffi import requests as cffi_req

    url = base_url.rstrip("/") + f"/api/v1/admin/accounts/{int(account_id)}"
    create_payload = _build_account_payload(email, token_data)
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
        resp = cffi_req.put(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Referer": base_url.rstrip("/") + "/admin/accounts",
            },
            impersonate="chrome",
            timeout=20,
        )
        return {"ok": resp.status_code in (200, 201), "status": resp.status_code, "body": resp.text[:300]}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)}


def _extract_sub2api_page_payload(body: Any) -> Dict[str, Any]:
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict):
            return data
        return body
    return {}


def _sub2api_identity_keys(email: str, refresh_token: str) -> List[str]:
    keys: List[str] = []
    email_norm = str(email or "").strip().lower()
    refresh_token_norm = str(refresh_token or "").strip()
    if email_norm:
        keys.append(f"email:{email_norm}")
    if refresh_token_norm:
        keys.append(f"rt:{refresh_token_norm}")
    return keys


def _load_local_token_identity_keys(max_files: int = 20000) -> set[str]:
    """
    预加载本地 token 文件身份键，用于运行前去重（跨线程/跨重启防重复落盘）。
    """
    keys: set[str] = set()
    if not os.path.isdir(TOKENS_DIR):
        return keys

    loaded = 0
    for fname in os.listdir(TOKENS_DIR):
        if loaded >= max_files:
            break
        if not str(fname).endswith(".json"):
            continue
        fpath = os.path.join(TOKENS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                td = json.load(f)
            if not isinstance(td, dict):
                continue
            email = str(td.get("email") or "").strip()
            refresh_token = str(td.get("refresh_token") or "").strip()
            keys.update(_sub2api_identity_keys(email, refresh_token))
            loaded += 1
        except Exception:
            continue
    return keys


def _sub2api_item_matches_identity(item: Dict[str, Any], email: str, refresh_token: str) -> bool:
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


def _find_existing_sub2api_account(
    base_url: str,
    bearer: str,
    email: str,
    refresh_token: str,
    max_pages: int = 8,
) -> Optional[Dict[str, Any]]:
    """
    在 Sub2Api 端查找是否已存在同一身份账号（email / refresh_token）。
    说明：
    - 主查 email（search 参数），并在返回项里再次精确匹配；
    - 若首次未命中，且提供了 refresh_token，会在有限页内继续扫一遍做 token 精确匹配。
    """
    from curl_cffi import requests as cffi_req

    url = base_url.rstrip("/") + "/api/v1/admin/accounts"
    email_norm = str(email or "").strip().lower()
    refresh_token_norm = str(refresh_token or "").strip()
    if not email_norm and not refresh_token_norm:
        return None

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json, text/plain, */*",
    }

    page_size = 100
    page = 1
    scanned_without_search = 0

    while page <= max_pages:
        params: Dict[str, Any] = {
            "page": page,
            "page_size": page_size,
            "platform": "openai",
            "type": "oauth",
        }
        if email_norm:
            params["search"] = email_norm

        try:
            resp = cffi_req.get(
                url,
                params=params,
                headers=headers,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                return None
            body = resp.json()
        except Exception:
            return None

        data = _extract_sub2api_page_payload(body)
        items = data.get("items") if isinstance(data.get("items"), list) else []
        for item in items:
            if isinstance(item, dict) and _sub2api_item_matches_identity(item, email_norm, refresh_token_norm):
                return item

        total_raw = data.get("total")
        try:
            total = int(total_raw) if total_raw is not None else 0
        except (TypeError, ValueError):
            total = 0
        if len(items) < page_size or (total > 0 and page * page_size >= total):
            break
        page += 1

    # search=xxx 未命中时，额外做有限页扫描，用 refresh_token 做兜底精确匹配
    if refresh_token_norm:
        page = 1
        while page <= 3:
            params = {
                "page": page,
                "page_size": page_size,
                "platform": "openai",
                "type": "oauth",
            }
            try:
                resp = cffi_req.get(
                    url,
                    params=params,
                    headers=headers,
                    impersonate="chrome",
                    timeout=15,
                )
                if resp.status_code != 200:
                    return None
                body = resp.json()
            except Exception:
                return None

            data = _extract_sub2api_page_payload(body)
            items = data.get("items") if isinstance(data.get("items"), list) else []
            for item in items:
                if isinstance(item, dict) and _sub2api_item_matches_identity(item, "", refresh_token_norm):
                    return item

            scanned_without_search += len(items)
            if len(items) < page_size or scanned_without_search >= 300:
                break
            page += 1

    return None


def _push_account_api_with_dedupe(
    base_url: str,
    bearer: str,
    email: str,
    token_data: Dict[str, Any],
    check_before: bool = True,
    check_after: bool = True,
) -> Dict[str, Any]:
    """
    上传前后做远端查重，避免重复创建同一账号。
    返回结构兼容 _push_account_api，额外包含:
    - skipped: bool
    - reason: str
    - existing_id: Optional[int]
    """
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    existing: Optional[Dict[str, Any]] = None

    if check_before:
        existing = _find_existing_sub2api_account(base_url, bearer, email, refresh_token)
        if existing is not None:
            existing_id = existing.get("id")
            existing_int = None
            try:
                existing_int = int(existing_id)
            except (TypeError, ValueError):
                existing_int = None
            if existing_int is not None and existing_int > 0:
                update_result = _update_sub2api_account_api(
                    base_url=base_url,
                    bearer=bearer,
                    account_id=existing_int,
                    email=email,
                    token_data=token_data,
                )
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

    result = _push_account_api(base_url, bearer, email, token_data)
    if result.get("ok"):
        result["skipped"] = False
        return result

    if check_after:
        existing = _find_existing_sub2api_account(base_url, bearer, email, refresh_token)
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
    return result


@app.post("/api/sync-batch")
async def api_sync_batch(req: BatchSyncRequest) -> Dict[str, Any]:
    """通过 HTTP API 将本地 Token 批量导入 Sub2Api 平台"""
    def _sync_batch() -> Dict[str, Any]:
        cfg = _get_sync_config()
        base_url = str(cfg.get("base_url", "") or "").strip()
        bearer = str(cfg.get("bearer_token", "") or "").strip()

        if not base_url:
            raise HTTPException(status_code=400, detail="请先配置 Sub2Api 平台地址")
        if not bearer:
            raise HTTPException(status_code=400, detail="Bearer Token 为空，请重新保存配置以自动登录获取")

        fnames = list(req.filenames or [])
        if not fnames:
            fnames = [f for f in os.listdir(TOKENS_DIR) if f.endswith(".json")]

        results = []
        for fname in fnames:
            if "/" in fname or "\\" in fname or ".." in fname:
                continue
            fpath = os.path.join(TOKENS_DIR, fname)
            if not os.path.isfile(fpath):
                results.append({"file": fname, "ok": False, "error": "文件不存在"})
                continue
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    token_data = json.load(f)
                email = token_data.get("email", fname)
                if _is_sub2api_uploaded(token_data):
                    results.append({"file": fname, "email": email, "ok": True, "skipped": True})
                    continue
                result = _push_account_api_with_dedupe(
                    base_url=base_url,
                    bearer=bearer,
                    email=str(email),
                    token_data=token_data,
                    check_before=True,
                    check_after=True,
                )
                results.append({"file": fname, "email": email, **result})
                if result["ok"]:
                    _mark_token_uploaded_platform(fpath, "sub2api")
                    reason = str(result.get("reason") or "")
                    if reason == "updated_existing_before_create":
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "success",
                            "message": f"[API] {email}: 命中已存在账号并更新凭据 (id={result.get('existing_id', '-')})",
                            "step": "sync",
                        })
                    elif result.get("skipped"):
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "success",
                            "message": f"[API] {email}: 同步成功",
                            "step": "sync",
                        })
                    else:
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "success",
                            "message": f"[API] {email}: 导入成功",
                            "step": "sync",
                        })
                else:
                    _state.broadcast({
                        "ts": datetime.now().strftime("%H:%M:%S"),
                        "level": "error",
                        "message": f"[API] {email}: 导入失败({result['status']}) {result['body'][:100]}",
                        "step": "sync",
                    })
            except Exception as e:
                results.append({"file": fname, "ok": False, "error": str(e)})

        ok_count = sum(1 for r in results if r.get("ok") and not r.get("skipped"))
        skip_count = sum(1 for r in results if r.get("skipped"))
        fail_count = sum(1 for r in results if not r.get("ok"))
        return {"total": len(results), "ok": ok_count, "skipped": skip_count, "fail": fail_count, "results": results}

    return await run_in_threadpool(_sync_batch)


# ==========================================
# Pool / Mail 配置 & 维护 API
# ==========================================


class PoolConfigRequest(BaseModel):
    cpa_base_url: str = ""
    cpa_token: str = ""
    min_candidates: int = 800
    used_percent_threshold: int = 95
    auto_maintain: bool = False
    maintain_interval_minutes: int = 30


class MailConfigRequest(BaseModel):
    mail_provider: str = "mailtm"
    mail_config: Dict[str, str] = {}
    mail_providers: List[str] = []
    mail_provider_configs: Dict[str, Dict[str, str]] = {}
    mail_strategy: str = "round_robin"
    use_register_version: Optional[str] = None


@app.get("/api/pool/config")
async def api_get_pool_config() -> Dict[str, Any]:
    cfg = _get_sync_config()
    token = str(cfg.get("cpa_token", ""))
    return {
        "cpa_base_url": cfg.get("cpa_base_url", ""),
        "cpa_token_preview": (token[:12] + "...") if len(token) > 12 else token,
        "min_candidates": cfg.get("min_candidates", 800),
        "used_percent_threshold": cfg.get("used_percent_threshold", 95),
        "auto_maintain": cfg.get("auto_maintain", False),
        "maintain_interval_minutes": cfg.get("maintain_interval_minutes", 30),
    }


@app.post("/api/pool/config")
async def api_set_pool_config(req: PoolConfigRequest) -> Dict[str, Any]:
    cfg = _get_sync_config()
    cfg["cpa_base_url"] = req.cpa_base_url.strip()
    cfg["cpa_token"] = req.cpa_token.strip() or str(cfg.get("cpa_token", "") or "").strip()
    cfg["min_candidates"] = req.min_candidates
    cfg["used_percent_threshold"] = req.used_percent_threshold
    cfg["auto_maintain"] = req.auto_maintain
    cfg["maintain_interval_minutes"] = max(5, req.maintain_interval_minutes)
    _save_sync_config(cfg)

    # 启停自动维护
    if req.auto_maintain:
        _start_auto_maintain()
    else:
        _stop_auto_maintain()

    return {"status": "saved"}


@app.get("/api/pool/status")
async def api_pool_status() -> Dict[str, Any]:
    pm = _get_pool_maintainer()
    if not pm:
        return {"configured": False, "error": "CPA 未配置"}
    status = await run_in_threadpool(pm.get_pool_status)
    status["configured"] = True
    return status


@app.post("/api/pool/check")
async def api_pool_check() -> Dict[str, Any]:
    pm = _get_pool_maintainer()
    if not pm:
        raise HTTPException(status_code=400, detail="CPA 未配置")
    result = await run_in_threadpool(pm.test_connection)
    return result


@app.post("/api/pool/maintain")
async def api_pool_maintain() -> Dict[str, Any]:
    pm = _get_pool_maintainer()
    if not pm:
        raise HTTPException(status_code=400, detail="CPA 未配置")
    if not _pool_maintain_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="维护任务已在执行中")
    try:
        result = await run_in_threadpool(pm.probe_and_clean_sync)
        _state.broadcast({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": f"[POOL] 维护完成: 无效 {result.get('invalid_count', 0)}, 已删除 {result.get('deleted_ok', 0)}",
            "step": "pool_maintain",
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _pool_maintain_lock.release()


@app.post("/api/pool/auto")
async def api_pool_auto(enable: bool = True) -> Dict[str, Any]:
    cfg = _get_sync_config()
    cfg["auto_maintain"] = enable
    _save_sync_config(cfg)
    if enable:
        _start_auto_maintain()
    else:
        _stop_auto_maintain()
    return {"auto_maintain": enable}


@app.get("/api/mail/config")
async def api_get_mail_config() -> Dict[str, Any]:
    cfg = _get_sync_config()
    # 兼容旧格式
    mail_cfg = dict(cfg.get("mail_config") or {})
    token = str(mail_cfg.get("bearer_token", ""))
    mail_cfg["bearer_token_preview"] = (token[:12] + "...") if len(token) > 12 else token
    mail_cfg.pop("bearer_token", None)
    key = str(mail_cfg.get("api_key", ""))
    mail_cfg["api_key_preview"] = (key[:8] + "...") if len(key) > 8 else key
    mail_cfg.pop("api_key", None)

    # 脱敏 provider_configs 中的敏感字段
    raw_configs = cfg.get("mail_provider_configs") or {}
    safe_configs: Dict[str, Dict] = {}
    for pname, pcfg in raw_configs.items():
        sc = dict(pcfg)
        for secret_key in ("bearer_token", "api_key", "admin_password"):
            val = str(sc.get(secret_key, ""))
            if val:
                sc[f"{secret_key}_preview"] = (val[:8] + "...") if len(val) > 8 else val
                sc.pop(secret_key, None)
        safe_configs[pname] = sc

    return {
        "mail_provider": cfg.get("mail_provider", "mailtm"),
        "mail_config": mail_cfg,
        "mail_providers": cfg.get("mail_providers", []),
        "mail_provider_configs": safe_configs,
        "mail_strategy": cfg.get("mail_strategy", "round_robin"),
        "use_register_version": cfg.get("use_register_version", "v1"),
    }


@app.post("/api/mail/config")
async def api_set_mail_config(req: MailConfigRequest) -> Dict[str, Any]:
    cfg = _get_sync_config()
    # 兼容旧格式
    cfg["mail_provider"] = req.mail_provider.strip() or "mailtm"
    cfg["mail_config"] = {str(k): str(v).strip() for k, v in (req.mail_config or {}).items()}

    # 新多提供商格式
    if req.mail_providers:
        cfg["mail_providers"] = [str(name).strip().lower() for name in req.mail_providers if str(name).strip()]
    cfg["mail_strategy"] = req.mail_strategy or "round_robin"

    existing_configs = cfg.get("mail_provider_configs") or {}
    for pname, pcfg in req.mail_provider_configs.items():
        existing_configs[str(pname).strip().lower()] = {
            str(k): str(v).strip() for k, v in (pcfg or {}).items()
        }
    cfg["mail_provider_configs"] = existing_configs

    # 保存注册流程版本配置
    if req.use_register_version is not None:
        version = str(req.use_register_version).lower()
        if version in ("v1", "v2", "v3"):
            cfg["use_register_version"] = version

    _save_sync_config(cfg)
    return {"status": "saved"}


@app.post("/api/mail/test")
async def api_mail_test() -> Dict[str, Any]:
    try:
        cfg = _get_sync_config()
        router = MultiMailRouter(cfg)
        results = []
        proxy = str(cfg.get("proxy") or _state.current_proxy or "").strip()
        for pname, provider in router.providers():
            ok, msg = await run_in_threadpool(provider.test_connection, proxy)
            results.append({"provider": pname, "ok": ok, "message": msg})
        all_ok = all(r["ok"] for r in results)
        return {"ok": all_ok, "results": results, "message": "全部通过" if all_ok else "部分失败"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def _try_auto_register() -> None:
    """维护后检查池状态，若不足则自动启动注册补充"""
    ts = datetime.now().strftime("%H:%M:%S")
    cfg = _get_sync_config()
    if not cfg.get("auto_register"):
        _state.broadcast({
            "ts": ts, "level": "info",
            "message": "[AUTO] 自动注册未开启，跳过（请勾选「池不足自动注册」并保存代理）",
            "step": "auto_register",
        })
        return
    proxy = str(cfg.get("proxy", "") or "").strip()
    proxy_pool_enabled = bool(cfg.get("proxy_pool_enabled", False))
    if not proxy and not proxy_pool_enabled:
        _state.broadcast({
            "ts": ts, "level": "warn",
            "message": "[AUTO] 跳过自动注册：未配置固定代理且代理池未启用，请先配置",
            "step": "auto_register",
        })
        return
    if _state.status != "idle":
        _state.broadcast({
            "ts": ts, "level": "info",
            "message": f"[AUTO] 跳过自动注册：当前状态 {_state.status}",
            "step": "auto_register",
        })
        return
    upload_mode = str(cfg.get("upload_mode", "snapshot") or "snapshot").strip().lower()
    if upload_mode not in ("snapshot", "decoupled"):
        upload_mode = "snapshot"
    gap = 0
    cpa_gap = 0
    sub2api_gap = 0
    api_error = False
    pm = _get_pool_maintainer(cfg)
    if pm:
        try:
            cpa_gap = pm.calculate_gap()
        except Exception as e:
            api_error = True
            _state.broadcast({
                "ts": ts, "level": "warn",
                "message": f"[AUTO] CPA 池状态查询失败，稍后重试: {e}",
                "step": "auto_register",
            })
    sm = _get_sub2api_maintainer(cfg)
    if sm and _is_auto_sync_enabled(cfg):
        try:
            sub2api_gap = sm.calculate_gap()
        except Exception as e:
            api_error = True
            _state.broadcast({
                "ts": ts, "level": "warn",
                "message": f"[AUTO] Sub2Api 池状态查询失败，稍后重试: {e}",
                "step": "auto_register",
            })
    elif sm:
        _state.broadcast({
            "ts": ts, "level": "info",
            "message": "[AUTO] Sub2Api 自动同步未开启，自动补号仅按 CPA 缺口执行",
            "step": "auto_register",
        })
    gap = (cpa_gap + sub2api_gap) if upload_mode == "snapshot" else max(cpa_gap, sub2api_gap)
    if api_error and gap <= 0:
        return
    if gap <= 0:
        _state.broadcast({
            "ts": ts, "level": "info",
            "message": "[AUTO] 池已充足，无需补充注册",
            "step": "auto_register",
        })
        return
    multithread = bool(cfg.get("multithread", False))
    thread_count = int(cfg.get("thread_count", 3))
    try:
        _state.start_task(
            proxy,
            worker_count=thread_count if multithread else 1,
            target_count=gap,
            cpa_target_count=cpa_gap if pm else 0,
            sub2api_target_count=sub2api_gap if sm and _is_auto_sync_enabled(cfg) else 0,
        )
        _state.broadcast({
            "ts": ts, "level": "success",
            "message": (
                f"[AUTO] 自动注册已启动：总补充 {gap}（CPA 缺口 {cpa_gap} / Sub2Api 缺口 {sub2api_gap} / "
                f"策略 {upload_mode}）"
            ),
            "step": "auto_register",
        })
    except RuntimeError as e:
        _state.broadcast({
            "ts": ts, "level": "warn",
            "message": f"[AUTO] 自动注册启动失败：{e}",
            "step": "auto_register",
        })


def _start_auto_maintain() -> None:
    global _auto_maintain_thread, _auto_maintain_stop
    cfg = _get_sync_config()
    interval = max(5, int(cfg.get("maintain_interval_minutes", 30))) * 60
    with _auto_maintain_ctl_lock:
        if _auto_maintain_thread and _auto_maintain_thread.is_alive():
            return
        stop_event = threading.Event()
        _auto_maintain_stop = stop_event

    def _loop(local_stop: threading.Event) -> None:
        while not local_stop.is_set():
            ts = datetime.now().strftime("%H:%M:%S")
            pm = _get_pool_maintainer()
            if not pm:
                _state.broadcast({
                    "ts": ts, "level": "warn",
                    "message": "[POOL] CPA 未配置（缺少 base_url 或 token），跳过自动维护",
                    "step": "pool_auto",
                })
            elif not _pool_maintain_lock.acquire(blocking=False):
                _state.broadcast({
                    "ts": ts, "level": "warn",
                    "message": "[POOL] 跳过自动维护：已有维护任务在执行",
                    "step": "pool_auto",
                })
            else:
                try:
                    _state.broadcast({
                        "ts": ts, "level": "info",
                        "message": "[POOL] 开始 CPA 自动维护（探活+清理）...",
                        "step": "pool_auto",
                    })
                    result = pm.probe_and_clean_sync()
                    total = result.get('total', 0)
                    candidates = result.get('candidates', 0)
                    invalid_count = result.get('invalid_count', 0)
                    deleted_ok = result.get('deleted_ok', 0)
                    deleted_fail = result.get('deleted_fail', 0)
                    healthy = candidates - invalid_count

                    if invalid_count == 0:
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "success",
                            "message": f"[POOL] 自动维护完成: 池内 {candidates} 个账号全部健康（总文件 {total}）",
                            "step": "pool_auto",
                        })
                    else:
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "info",
                            "message": (
                                f"[POOL] 自动维护完成: 总 {candidates}, 健康 {healthy}, "
                                f"无效 {invalid_count}, 已删除 {deleted_ok}"
                                + (f", 删除失败 {deleted_fail}" if deleted_fail else "")
                            ),
                            "step": "pool_auto",
                        })
                except Exception as e:
                    _state.broadcast({
                        "ts": datetime.now().strftime("%H:%M:%S"),
                        "level": "error",
                        "message": f"[POOL] 自动维护异常: {e}",
                        "step": "pool_auto",
                    })
                finally:
                    _pool_maintain_lock.release()
                _try_auto_register()

            next_ts = datetime.now().strftime("%H:%M:%S")
            _state.broadcast({
                "ts": next_ts, "level": "info",
                "message": f"[POOL] 下次自动维护: {interval // 60} 分钟后",
                "step": "pool_auto",
            })
            local_stop.wait(interval)

    thread = threading.Thread(target=_loop, args=(stop_event,), daemon=True)
    with _auto_maintain_ctl_lock:
        _auto_maintain_thread = thread
    thread.start()


def _stop_auto_maintain() -> None:
    global _auto_maintain_thread, _auto_maintain_stop
    with _auto_maintain_ctl_lock:
        stop_event = _auto_maintain_stop
        thread = _auto_maintain_thread
    if stop_event:
        stop_event.set()
    if thread and thread.is_alive():
        thread.join(timeout=5)
    with _auto_maintain_ctl_lock:
        if _auto_maintain_thread is thread and (thread is None or not thread.is_alive()):
            _auto_maintain_thread = None
            _auto_maintain_stop = None


# ==========================================
# Sub2Api 池维护 API & 自动维护
# ==========================================

_sub2api_auto_maintain_thread: Optional[threading.Thread] = None
_sub2api_auto_maintain_stop: Optional[threading.Event] = None
_sub2api_auto_maintain_ctl_lock = threading.Lock()
_sub2api_maintain_lock = threading.Lock()


class Sub2ApiDedupeRequest(BaseModel):
    dry_run: bool = True
    timeout: int = 20


class Sub2ApiAccountActionRequest(BaseModel):
    account_ids: List[int] = Field(default_factory=list)
    timeout: int = 30


class Sub2ApiExceptionHandleRequest(Sub2ApiAccountActionRequest):
    delete_unresolved: bool = True


@app.get("/api/sub2api/accounts")
async def api_sub2api_accounts(
    page: int = 1,
    page_size: int = 20,
    status: str = "all",
    keyword: str = "",
) -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        return {"configured": False, "error": "Sub2Api 未配置", "items": []}
    cfg = _get_sync_config()
    snapshot = await run_in_threadpool(
        lambda: _get_sub2api_accounts_inventory_snapshot(sm, cfg)
    )
    filtered_items = _filter_sub2api_account_items(
        list(snapshot.get("items") or []),
        status=status,
        keyword=keyword,
    )
    paged = _paginate_sub2api_account_items(filtered_items, page=page, page_size=page_size)
    return {
        "configured": True,
        "total": int(snapshot.get("total", 0)),
        "error_count": int(snapshot.get("error_count", 0)),
        "duplicate_groups": int(snapshot.get("duplicate_groups", 0)),
        "duplicate_accounts": int(snapshot.get("duplicate_accounts", 0)),
        "items": paged["items"],
        "page": paged["page"],
        "page_size": paged["page_size"],
        "filtered_total": paged["filtered_total"],
        "total_pages": paged["total_pages"],
        "status": str(status or "all"),
        "keyword": str(keyword or ""),
    }


@app.post("/api/sub2api/accounts/probe")
async def api_sub2api_accounts_probe(req: Sub2ApiAccountActionRequest) -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        raise HTTPException(status_code=400, detail="Sub2Api 未配置")
    if not req.account_ids:
        raise HTTPException(status_code=400, detail="请先选择至少一个账号")
    if not _sub2api_maintain_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Sub2Api 账号任务已在执行中")
    try:
        timeout = max(5, int(req.timeout))
        result = await run_in_threadpool(
            lambda: sm.probe_accounts(req.account_ids, timeout=timeout)
        )
        _state.broadcast({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": (
                f"[Sub2Api] 账号测活: 请求 {result.get('requested', 0)}, "
                f"刷新成功 {result.get('refreshed_ok', 0)}, "
                f"恢复 {result.get('recovered', 0)}, "
                f"仍异常 {result.get('still_abnormal', 0)}"
            ),
            "step": "sub2api_accounts_probe",
        })
        _clear_sub2api_accounts_cache()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _sub2api_maintain_lock.release()


@app.post("/api/sub2api/accounts/delete")
async def api_sub2api_accounts_delete(req: Sub2ApiAccountActionRequest) -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        raise HTTPException(status_code=400, detail="Sub2Api 未配置")
    if not req.account_ids:
        raise HTTPException(status_code=400, detail="请先选择至少一个账号")
    if not _sub2api_maintain_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Sub2Api 账号任务已在执行中")
    try:
        timeout = max(5, int(req.timeout))
        result = await run_in_threadpool(
            lambda: sm.delete_accounts_batch(req.account_ids, timeout=timeout)
        )
        _state.broadcast({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": (
                f"[Sub2Api] 批量删除: 请求 {result.get('requested', 0)}, "
                f"删除成功 {result.get('deleted_ok', 0)}, "
                f"删除失败 {result.get('deleted_fail', 0)}"
            ),
            "step": "sub2api_accounts_delete",
        })
        _clear_sub2api_accounts_cache()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _sub2api_maintain_lock.release()


@app.post("/api/sub2api/accounts/handle-exception")
async def api_sub2api_accounts_handle_exception(req: Sub2ApiExceptionHandleRequest) -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        raise HTTPException(status_code=400, detail="Sub2Api 未配置")
    if not _sub2api_maintain_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Sub2Api 账号任务已在执行中")
    try:
        timeout = max(5, int(req.timeout))
        result = await run_in_threadpool(
            lambda: sm.handle_exception_accounts(
                req.account_ids or None,
                timeout=timeout,
                delete_unresolved=bool(req.delete_unresolved),
            )
        )
        _state.broadcast({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": (
                f"[Sub2Api] 异常处理: 目标 {result.get('targeted', 0)}, "
                f"恢复 {result.get('recovered', 0)}, "
                f"删除 {result.get('deleted_ok', 0)}(失败 {result.get('deleted_fail', 0)})"
            ),
            "step": "sub2api_accounts_exception",
        })
        _clear_sub2api_accounts_cache()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _sub2api_maintain_lock.release()


@app.get("/api/sub2api/pool/status")
async def api_sub2api_pool_status() -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        return {"configured": False, "error": "Sub2Api 未配置"}
    status = await run_in_threadpool(sm.get_pool_status)
    status["configured"] = True
    return status


@app.post("/api/sub2api/pool/check")
async def api_sub2api_pool_check() -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        raise HTTPException(status_code=400, detail="Sub2Api 未配置")
    result = await run_in_threadpool(sm.test_connection)
    return result


@app.post("/api/sub2api/pool/maintain")
async def api_sub2api_pool_maintain() -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        raise HTTPException(status_code=400, detail="Sub2Api 未配置")
    if not _sub2api_maintain_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Sub2Api 维护任务已在执行中")
    try:
        cfg = _get_sync_config()
        actions = _get_sub2api_maintain_actions(cfg)
        result = await run_in_threadpool(
            lambda: sm.probe_and_clean_sync(actions=actions)
        )
        _state.broadcast({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": "info",
            "message": _format_sub2api_maintain_result_message(result),
            "step": "sub2api_maintain",
        })
        _clear_sub2api_accounts_cache()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _sub2api_maintain_lock.release()


@app.post("/api/sub2api/pool/dedupe")
async def api_sub2api_pool_dedupe(req: Sub2ApiDedupeRequest) -> Dict[str, Any]:
    sm = _get_sub2api_maintainer()
    if not sm:
        raise HTTPException(status_code=400, detail="Sub2Api 未配置")
    if not _sub2api_maintain_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Sub2Api 维护任务已在执行中")
    try:
        timeout = max(5, int(req.timeout))
        dry_run = bool(req.dry_run)
        result = await run_in_threadpool(
            lambda: sm.dedupe_duplicate_accounts(timeout=timeout, dry_run=dry_run)
        )
        if dry_run:
            _state.broadcast({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "level": "info",
                "message": (
                    f"[Sub2Api] 重复预检完成: 重复组 {result.get('duplicate_groups', 0)}, "
                    f"可删 {result.get('to_delete', 0)}"
                ),
                "step": "sub2api_dedupe",
            })
        else:
            _state.broadcast({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "level": "info",
                "message": (
                    f"[Sub2Api] 重复清理完成: 删除成功 {result.get('deleted_ok', 0)}, "
                    f"删除失败 {result.get('deleted_fail', 0)}"
                ),
                "step": "sub2api_dedupe",
            })
        _clear_sub2api_accounts_cache()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _sub2api_maintain_lock.release()


def _start_sub2api_auto_maintain() -> None:
    global _sub2api_auto_maintain_thread, _sub2api_auto_maintain_stop
    cfg = _get_sync_config()
    interval = max(5, int(cfg.get("sub2api_maintain_interval_minutes", 30))) * 60
    with _sub2api_auto_maintain_ctl_lock:
        if _sub2api_auto_maintain_thread and _sub2api_auto_maintain_thread.is_alive():
            return
        stop_event = threading.Event()
        _sub2api_auto_maintain_stop = stop_event

    def _loop(local_stop: threading.Event) -> None:
        while not local_stop.is_set():
            sm = _get_sub2api_maintainer()
            if sm:
                if not _sub2api_maintain_lock.acquire(blocking=False):
                    _state.broadcast({
                        "ts": datetime.now().strftime("%H:%M:%S"),
                        "level": "warn",
                        "message": "[Sub2Api] 跳过自动维护：已有维护任务在执行",
                        "step": "sub2api_auto",
                    })
                else:
                    try:
                        current_cfg = _get_sync_config()
                        result = sm.probe_and_clean_sync(
                            actions=_get_sub2api_maintain_actions(current_cfg)
                        )
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "info",
                            "message": _format_sub2api_maintain_result_message(result, auto=True),
                            "step": "sub2api_auto",
                        })
                        _clear_sub2api_accounts_cache()
                    except Exception as e:
                        _state.broadcast({
                            "ts": datetime.now().strftime("%H:%M:%S"),
                            "level": "error",
                            "message": f"[Sub2Api] 自动维护异常: {e}",
                            "step": "sub2api_auto",
                        })
                    finally:
                        _sub2api_maintain_lock.release()
                    _try_auto_register()
            local_stop.wait(interval)

    thread = threading.Thread(target=_loop, args=(stop_event,), daemon=True)
    with _sub2api_auto_maintain_ctl_lock:
        _sub2api_auto_maintain_thread = thread
    thread.start()


def _stop_sub2api_auto_maintain() -> None:
    global _sub2api_auto_maintain_thread, _sub2api_auto_maintain_stop
    with _sub2api_auto_maintain_ctl_lock:
        stop_event = _sub2api_auto_maintain_stop
        thread = _sub2api_auto_maintain_thread
    if stop_event:
        stop_event.set()
    if thread and thread.is_alive():
        thread.join(timeout=5)
    with _sub2api_auto_maintain_ctl_lock:
        if _sub2api_auto_maintain_thread is thread and (thread is None or not thread.is_alive()):
            _sub2api_auto_maintain_thread = None
            _sub2api_auto_maintain_stop = None


@app.on_event("startup")
async def _startup_restore_background_tasks() -> None:
    _service_shutdown_event.clear()
    cfg = _get_sync_config()
    if cfg.get("auto_maintain"):
        _start_auto_maintain()
    if cfg.get("sub2api_auto_maintain"):
        _start_sub2api_auto_maintain()


@app.on_event("shutdown")
async def _shutdown_background_tasks() -> None:
    _service_shutdown_event.set()
    _stop_auto_maintain()
    _stop_sub2api_auto_maintain()


# 挂载静态文件
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ==========================================
# 入口（兼容直接运行）
# ==========================================

if __name__ == "__main__":
    from .__main__ import main
    main()
