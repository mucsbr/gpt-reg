"""
本地候选池自动维护。

扫描 data/tokens 中被标记为 cooling / reauth_pending 的本地 token，
尝试 refresh、查额度、必要时重认证，并在恢复后回推 CPA。
"""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from .mail_providers import create_provider_by_name
from .pool_maintainer import PoolMaintainer
from .register import CLIENT_ID, DEFAULT_REDIRECT_URI, EventEmitter, _augment_token_payload, _build_token_result
from .register_v3 import _create_session, _perform_login

logger = logging.getLogger(__name__)

AUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
REAUTH_RETRY_SECONDS = 6 * 3600
NETWORK_RETRY_SECONDS = 3600
DEFAULT_RESET_GRACE_SECONDS = 600
LOCAL_STATUS_COOLING = "cooling"
LOCAL_STATUS_REAUTH = "reauth_pending"
ELIGIBLE_STATUSES = {LOCAL_STATUS_COOLING, LOCAL_STATUS_REAUTH}

LOCAL_RECOVERED_STATUSES = {"ok", "healthy", "uploaded"}
DEFAULT_MAIL_PROVIDER = "cloudflare_temp_email"


@dataclass
class LocalPoolStats:
    total: int = 0
    cooling: int = 0
    reauth_pending: int = 0
    eligible: int = 0
    uploaded: int = 0
    waiting: int = 0
    deleted: int = 0
    failed: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "cooling": self.cooling,
            "reauth_pending": self.reauth_pending,
            "eligible": self.eligible,
            "uploaded": self.uploaded,
            "waiting": self.waiting,
            "deleted": self.deleted,
            "failed": self.failed,
        }


@dataclass
class LocalPoolResult:
    action: str
    message: str
    level: str = "info"
    updated_data: Optional[Dict[str, Any]] = None
    next_status: Optional[str] = None
    next_check_at: Optional[datetime] = None
    last_used_percent: Optional[float] = None
    recovered_status: Optional[str] = None
    delete_file: bool = False


class LocalPoolMaintainer:
    def __init__(self, tokens_dir: str | Path, proxy: str = ""):
        self.tokens_dir = Path(tokens_dir)
        self.proxy = str(proxy or "").strip()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _now_ts() -> float:
        return time.time()

    @staticmethod
    def _to_iso(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _from_iso(raw: Any) -> Optional[datetime]:
        text = str(raw or "").strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text).astimezone(timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.stem}.tmp{path.suffix}")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)

    def _load_token_file(self, path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}

    def _mark_file(
        self,
        filepath: Path,
        *,
        token_data: Dict[str, Any],
        status: Optional[str],
        next_check_at: Optional[datetime],
        last_used_percent: Optional[float] = None,
    ) -> Dict[str, Any]:
        updated = dict(token_data)
        if not str(updated.get("email") or "").strip() and filepath.name:
            updated["email"] = filepath.stem
        if status:
            updated["local_status"] = status
        else:
            updated.pop("local_status", None)
        if next_check_at:
            updated["next_check_at"] = self._to_iso(next_check_at)
        else:
            updated.pop("next_check_at", None)
        if last_used_percent is None:
            updated.pop("last_used_percent", None)
        else:
            updated["last_used_percent"] = round(float(last_used_percent), 2)
        self._write_json_atomic(filepath, updated)
        return updated

    def _clear_local_status(self, filepath: Path, token_data: Dict[str, Any]) -> Dict[str, Any]:
        updated = dict(token_data)
        if not str(updated.get("email") or "").strip() and filepath.name:
            updated["email"] = filepath.stem
        updated.pop("local_status", None)
        updated.pop("next_check_at", None)
        updated.pop("last_used_percent", None)
        if not str(updated.get("local_recovered_status") or "").strip():
            updated["local_recovered_status"] = "ok"
        self._write_json_atomic(filepath, updated)
        return updated

    def scan_eligible_files(self) -> Tuple[List[Tuple[Path, Dict[str, Any]]], LocalPoolStats]:
        stats = LocalPoolStats()
        eligible: List[Tuple[Path, Dict[str, Any]]] = []
        now = self._now()
        if not self.tokens_dir.exists():
            return eligible, stats
        for path in sorted(self.tokens_dir.glob("*.json")):
            try:
                token_data = self._load_token_file(path)
            except Exception:
                logger.warning("读取 token 文件失败: %s", path)
                continue
            stats.total += 1
            status = str(token_data.get("local_status") or "").strip().lower()
            if not status:
                status = LOCAL_STATUS_COOLING
            if status == LOCAL_STATUS_COOLING:
                stats.cooling += 1
            elif status == LOCAL_STATUS_REAUTH:
                stats.reauth_pending += 1
            if status not in ELIGIBLE_STATUSES:
                continue
            next_check = self._from_iso(token_data.get("next_check_at"))
            if next_check and next_check > now:
                continue
            candidate_data = dict(token_data)
            if not str(candidate_data.get("local_status") or "").strip():
                candidate_data["local_status"] = status
            if not candidate_data.get("next_check_at"):
                candidate_data["next_check_at"] = self._to_iso(now)
            stats.eligible += 1
            eligible.append((path, candidate_data))
        return eligible, stats

    def get_status(self) -> Dict[str, int]:
        _, stats = self.scan_eligible_files()
        return {"total": stats.total, "cooling": stats.cooling, "reauth_pending": stats.reauth_pending, "eligible": stats.eligible}

    def _refresh_token(self, refresh_token: str, proxy: str = "") -> Dict[str, Any]:
        session = requests.Session()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        resp = session.post(
            AUTH_TOKEN_URL,
            headers={"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
            data={
                "client_id": CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "redirect_uri": DEFAULT_REDIRECT_URI,
            },
            timeout=30,
        )
        text = str(resp.text or "")
        try:
            body = resp.json()
        except Exception:
            body = {}
        if resp.status_code != 200:
            raise RuntimeError(text[:500] or f"HTTP {resp.status_code}")
        return body if isinstance(body, dict) else {}

    def _check_usage(self, access_token: str, account_id: str, proxy: str = "") -> Tuple[float, Optional[datetime]]:
        session = requests.Session()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0",
        }
        if account_id:
            headers["Chatgpt-Account-Id"] = account_id
        resp = session.get(USAGE_URL, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError((resp.text or f"HTTP {resp.status_code}")[:500])
        data = resp.json() if resp.content else {}
        primary = ((data.get("rate_limit") or {}).get("primary_window") or {}) if isinstance(data, dict) else {}
        used_percent = float(primary.get("used_percent") or 0)
        reset_at_raw = primary.get("reset_at")
        reset_at = None
        if reset_at_raw:
            try:
                reset_at = datetime.fromtimestamp(float(reset_at_raw), tz=timezone.utc)
            except Exception:
                reset_at = None
        return used_percent, reset_at

    @staticmethod
    def _classify_error(text: str) -> str:
        lowered = str(text or "").lower()
        if "deactivated" in lowered or "account_deactivated" in lowered:
            return "deactivated"
        if (
            "token_invalidated" in lowered
            or "invalidated" in lowered
            or "401" in lowered
            or "unauthorized" in lowered
            or "refresh_token_reused" in lowered
            or "already been used to generate a new access token" in lowered
        ):
            return "invalid"
        return "retry"

    def _reauth_by_login(
        self,
        token_data: Dict[str, Any],
        proxy: str,
        emitter: EventEmitter,
    ) -> Optional[Dict[str, Any]]:
        provider_name = str(token_data.get("mail_provider") or DEFAULT_MAIL_PROVIDER).strip().lower()
        mail_credential = str(token_data.get("mail_credential") or "").strip()
        email = str(token_data.get("email") or "").strip()
        password = str(token_data.get("account_password") or "").strip()
        if not provider_name or not email or not password:
            raise RuntimeError("缺少重认证所需邮箱信息")
        if not mail_credential:
            raise RuntimeError("missing mail_credential")
        provider_cfg = self._resolve_mail_provider_config(provider_name)
        provider = create_provider_by_name(provider_name, provider_cfg)
        try:
            setattr(provider, "provider_name", provider_name)
        except Exception:
            pass
        session = _create_session(proxy)
        login_emitter = emitter.bind(mail_provider=provider_name)
        token_payload = _perform_login(
            session=session,
            email=email,
            password=password,
            device_id="",
            code_verifier="",
            emitter=login_emitter,
            mail_provider=provider,
            otp_token=mail_credential,
            proxy_str=proxy,
            stop_event=None,
            used_otp_codes=None,
        )
        if not token_payload:
            return None
        token_json = _augment_token_payload(
            _build_token_result(token_payload, account_password=password),
            account_password=password,
            mail_provider_name=provider_name,
            mail_credential=mail_credential,
        )
        return json.loads(token_json)

    def _resolve_mail_provider_config(self, provider_name: str) -> Dict[str, Any]:
        from . import CONFIG_FILE
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                cfg = json.load(handle)
        except Exception:
            cfg = {}
        provider_configs = cfg.get("mail_provider_configs") or {}
        raw = provider_configs.get(provider_name) or {}
        return raw if isinstance(raw, dict) else {}

    @staticmethod
    def _emit_result_message(emitter: EventEmitter, result: LocalPoolResult) -> None:
        level = str(result.level or "info").lower()
        if level == "success":
            emitter.success(result.message, step="local_pool")
        elif level == "warn":
            emitter.warn(result.message, step="local_pool")
        elif level == "error":
            emitter.error(result.message, step="local_pool")
        else:
            emitter.info(result.message, step="local_pool")

    def _handle_invalid_token(
        self,
        *,
        token_data: Dict[str, Any],
        email: str,
        proxy: str,
        emitter: EventEmitter,
    ) -> LocalPoolResult:
        if not str(token_data.get("mail_credential") or "").strip():
            return LocalPoolResult(
                action="delete",
                message=f"[LOCAL] {email}: 需要重认证但缺少 mail_credential，删除",
                delete_file=True,
            )
        emitter.info(f"[LOCAL] {email}: token 失效，重认证中...", step="local_pool")
        try:
            reauthed = self._reauth_by_login(token_data, proxy, emitter)
        except Exception as reauth_exc:
            reauth_reason = self._classify_error(str(reauth_exc))
            if reauth_reason == "deactivated":
                return LocalPoolResult(
                    action="delete",
                    message=f"[LOCAL] {email}: 重认证失败，删除",
                    delete_file=True,
                )
            return LocalPoolResult(
                action="waiting",
                message=f"[LOCAL] {email}: 重认证失败，6h 后再试，原因: {reauth_exc}",
                level="warn",
                updated_data=token_data,
                next_status=LOCAL_STATUS_REAUTH,
                next_check_at=self._now() + timedelta(seconds=REAUTH_RETRY_SECONDS),
                last_used_percent=token_data.get("last_used_percent"),
            )
        if not reauthed:
            return LocalPoolResult(
                action="waiting",
                message=f"[LOCAL] {email}: 重认证失败，6h 后再试",
                level="warn",
                updated_data=token_data,
                next_status=LOCAL_STATUS_REAUTH,
                next_check_at=self._now() + timedelta(seconds=REAUTH_RETRY_SECONDS),
                last_used_percent=token_data.get("last_used_percent"),
            )
        return LocalPoolResult(
            action="reauthed",
            message=f"[LOCAL] {email}: 重认证成功",
            updated_data=reauthed,
        )

    def _handle_deactivated(self, email: str, reason_text: str = "") -> LocalPoolResult:
        suffix = f"，原因: {reason_text}" if reason_text else ""
        return LocalPoolResult(
            action="delete",
            message=f"[LOCAL] {email}: 账号封禁（deactivated），删除{suffix}",
            delete_file=True,
        )

    def _upload_to_cpa(self, filename: str, token_data: Dict[str, Any], proxy: str, cpa_maintainer: PoolMaintainer) -> bool:
        return cpa_maintainer.upload_token(filename, token_data, proxy=proxy)

    def _schedule_after_reset(self, reset_at: Optional[datetime], fallback_hours: int) -> datetime:
        if reset_at:
            return reset_at + timedelta(seconds=DEFAULT_RESET_GRACE_SECONDS)
        return self._now() + timedelta(hours=max(1, fallback_hours))

    def _process_candidate(
        self,
        path: Path,
        token_data: Dict[str, Any],
        threshold: float,
        retry_hours: int,
        proxy: str,
        emitter: EventEmitter,
    ) -> LocalPoolResult:
        email = str(token_data.get("email") or path.name).strip() or path.name
        try:
            refreshed_data = token_data
            refresh_source = "refresh"
            try:
                refreshed_payload = self._refresh_token(str(token_data.get("refresh_token") or "").strip(), proxy)
                merged_json = _augment_token_payload(
                    _build_token_result(refreshed_payload, account_password=str(token_data.get("account_password") or "")),
                    account_password=str(token_data.get("account_password") or ""),
                    mail_provider_name=str(token_data.get("mail_provider") or ""),
                    mail_credential=str(token_data.get("mail_credential") or ""),
                )
                refreshed_data = json.loads(merged_json)
            except Exception as exc:
                reason = self._classify_error(str(exc))
                if reason == "deactivated":
                    return self._handle_deactivated(email=email, reason_text=str(exc))
                if reason == "invalid":
                    reauth_result = self._handle_invalid_token(
                        token_data=token_data,
                        email=email,
                        proxy=proxy,
                        emitter=emitter,
                    )
                    if reauth_result.action != "reauthed":
                        return reauth_result
                    refreshed_data = dict(reauth_result.updated_data or token_data)
                    refresh_source = "reauth"
                else:
                    return LocalPoolResult(
                        action="waiting",
                        message=f"[LOCAL] {email}: refresh 失败，1h 后再试，原因: {exc}",
                        level="warn",
                        updated_data=token_data,
                        next_status=str(token_data.get("local_status") or LOCAL_STATUS_COOLING),
                        next_check_at=self._now() + timedelta(seconds=NETWORK_RETRY_SECONDS),
                        last_used_percent=token_data.get("last_used_percent"),
                    )

            try:
                used_percent, reset_at = self._check_usage(
                    str(refreshed_data.get("access_token") or "").strip(),
                    str(refreshed_data.get("account_id") or "").strip(),
                    proxy,
                )
            except Exception as usage_exc:
                usage_reason = self._classify_error(str(usage_exc))
                if usage_reason == "deactivated":
                    return self._handle_deactivated(email=email, reason_text=str(usage_exc))
                if usage_reason == "invalid":
                    reauth_result = self._handle_invalid_token(
                        token_data=refreshed_data,
                        email=email,
                        proxy=proxy,
                        emitter=emitter,
                    )
                    if reauth_result.action != "reauthed":
                        return reauth_result
                    refreshed_data = dict(reauth_result.updated_data or refreshed_data)
                    refresh_source = "reauth"
                    used_percent, reset_at = self._check_usage(
                        str(refreshed_data.get("access_token") or "").strip(),
                        str(refreshed_data.get("account_id") or "").strip(),
                        proxy,
                    )
                else:
                    return LocalPoolResult(
                        action="waiting",
                        message=f"[LOCAL] {email}: usage 检查失败，1h 后再试，原因: {usage_exc}",
                        level="warn",
                        updated_data=refreshed_data,
                        next_status=str(refreshed_data.get("local_status") or LOCAL_STATUS_COOLING),
                        next_check_at=self._now() + timedelta(seconds=NETWORK_RETRY_SECONDS),
                        last_used_percent=refreshed_data.get("last_used_percent"),
                    )

            action_label = "重认证成功" if refresh_source == "reauth" else "refresh 成功"
            if used_percent < threshold:
                return LocalPoolResult(
                    action="recovered",
                    message=f"[LOCAL] {email}: {action_label}，用量 {used_percent:.1f}% < {threshold:.0f}%",
                    level="success",
                    updated_data=refreshed_data,
                    last_used_percent=used_percent,
                )
            next_check = self._schedule_after_reset(reset_at, retry_hours)
            return LocalPoolResult(
                action="waiting",
                message=f"[LOCAL] {email}: refresh 成功，用量 {used_percent:.1f}%，继续等待（{retry_hours}h 后）",
                level="info",
                updated_data=refreshed_data,
                next_status=LOCAL_STATUS_COOLING,
                next_check_at=next_check,
                last_used_percent=used_percent,
            )
        except Exception as exc:
            return LocalPoolResult(
                action="failed",
                message=f"[LOCAL] {email}: 维护异常 {exc}",
                level="error",
                updated_data=token_data,
                next_status=str(token_data.get("local_status") or LOCAL_STATUS_COOLING),
                next_check_at=self._now() + timedelta(seconds=NETWORK_RETRY_SECONDS),
                last_used_percent=token_data.get("last_used_percent"),
            )

    def run_cycle(
        self,
        emitter: EventEmitter,
        cpa_maintainer: Optional[PoolMaintainer],
        cfg: Dict[str, Any],
    ) -> Dict[str, Any]:
        threshold = float(cfg.get("local_refresh_threshold_pct", 60) or 60)
        retry_hours = int(cfg.get("local_check_interval_hours", 6) or 6)
        proxy = str(cfg.get("proxy") or self.proxy or "").strip()
        eligible, stats = self.scan_eligible_files()

        emitter.info("[LOCAL] 开始本地池维护扫描...", step="local_pool")
        emitter.info(
            f"[LOCAL] 待检查: {stats.eligible} 个（cooling: {stats.cooling}, reauth: {stats.reauth_pending}）",
            step="local_pool",
        )

        if eligible:
            try:
                worker_count = max(1, min(int(cfg.get("local_maintain_thread_count", cfg.get("thread_count", 3)) or 3), 10, len(eligible)))
            except Exception:
                worker_count = max(1, min(3, len(eligible)))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_candidate = {
                    executor.submit(
                        self._process_candidate,
                        path,
                        token_data,
                        threshold,
                        retry_hours,
                        proxy,
                        emitter,
                    ): (path, token_data)
                    for path, token_data in eligible
                }
                for future in as_completed(future_to_candidate):
                    path, token_data = future_to_candidate[future]
                    email = str(token_data.get("email") or path.name).strip() or path.name
                    filename = path.name
                    try:
                        result = future.result()
                    except Exception as future_exc:
                        result = LocalPoolResult(
                            action="failed",
                            message=f"[LOCAL] {email}: 维护异常 {future_exc}",
                            level="error",
                            updated_data=token_data,
                            next_status=str(token_data.get("local_status") or LOCAL_STATUS_COOLING),
                            next_check_at=self._now() + timedelta(seconds=NETWORK_RETRY_SECONDS),
                            last_used_percent=token_data.get("last_used_percent"),
                        )

                    try:
                        result_data = dict(result.updated_data or token_data)
                        if result.delete_file:
                            path.unlink(missing_ok=True)
                            stats.deleted += 1
                            self._emit_result_message(emitter, result)
                            continue
                        if result.action == "recovered":
                            if cpa_maintainer:
                                ok = self._upload_to_cpa(filename, result_data, proxy, cpa_maintainer)
                                if ok:
                                    result_data["local_recovered_status"] = "uploaded"
                                    self._clear_local_status(path, result_data)
                                    stats.uploaded += 1
                                    emitter.success(f"{result.message}，推送 CPA", step="local_pool")
                                else:
                                    self._mark_file(
                                        path,
                                        token_data=result_data,
                                        status=LOCAL_STATUS_COOLING,
                                        next_check_at=self._now() + timedelta(seconds=NETWORK_RETRY_SECONDS),
                                        last_used_percent=result.last_used_percent,
                                    )
                                    stats.failed += 1
                                    emitter.error(f"[LOCAL] {email}: 回推 CPA 失败，1h 后再试", step="local_pool")
                            else:
                                result_data["local_recovered_status"] = "healthy"
                                self._clear_local_status(path, result_data)
                                stats.uploaded += 1
                                emitter.success(f"{result.message}，已恢复但未配置 CPA", step="local_pool")
                            continue
                        if result.action == "waiting":
                            self._mark_file(
                                path,
                                token_data=result_data,
                                status=result.next_status or str(result_data.get("local_status") or LOCAL_STATUS_COOLING),
                                next_check_at=result.next_check_at,
                                last_used_percent=result.last_used_percent,
                            )
                            stats.waiting += 1
                            self._emit_result_message(emitter, result)
                            continue
                        if result.action == "failed":
                            self._mark_file(
                                path,
                                token_data=result_data,
                                status=result.next_status or str(result_data.get("local_status") or LOCAL_STATUS_COOLING),
                                next_check_at=result.next_check_at,
                                last_used_percent=result.last_used_percent,
                            )
                            stats.failed += 1
                            self._emit_result_message(emitter, result)
                            continue
                        raise RuntimeError(f"unsupported action: {result.action}")
                    except Exception as exc:
                        self._mark_file(
                            path,
                            token_data=token_data,
                            status=str(token_data.get("local_status") or LOCAL_STATUS_COOLING),
                            next_check_at=self._now() + timedelta(seconds=NETWORK_RETRY_SECONDS),
                            last_used_percent=token_data.get("last_used_percent"),
                        )
                        stats.failed += 1
                        emitter.error(f"[LOCAL] {email}: 维护异常 {exc}", step="local_pool")

        emitter.info(
            f"[LOCAL] 维护完成: 回推 {stats.uploaded}, 等待 {stats.waiting}, 删除 {stats.deleted}",
            step="local_pool",
        )
        return stats.as_dict()
