import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import socket
import hashlib
import base64
import threading
import argparse
import queue
import tempfile
from http.cookies import SimpleCookie
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional, Callable
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests

# ==========================================
# 日志事件发射器
# ==========================================


class EventEmitter:
    """
    将注册流程中的日志事件发射到队列，供 SSE 消费。
    同时支持 CLI 模式（直接 print）。
    """

    def __init__(
        self,
        q: Optional[queue.Queue] = None,
        cli_mode: bool = False,
        defaults: Optional[Dict[str, Any]] = None,
    ):
        self._q = q
        self._cli_mode = cli_mode
        self._defaults = dict(defaults or {})

    def emit(self, level: str, message: str, step: str = "", **extra: Any) -> None:
        """
        level: "info" | "success" | "error" | "warn"
        step:  可选的流程阶段标识，如 "check_proxy" / "create_email" 等
        """
        ts = datetime.now().strftime("%H:%M:%S")
        event = {
            "ts": ts,
            "level": level,
            "message": message,
            "step": step,
        }
        if self._defaults:
            event.update(self._defaults)
        if extra:
            event.update({k: v for k, v in extra.items() if v is not None})
        if self._cli_mode:
            prefix_map = {
                "info": "[*]",
                "success": "[+]",
                "error": "[Error]",
                "warn": "[!]",
            }
            prefix = prefix_map.get(level, "[*]")
            print(f"{prefix} {message}")
        if self._q is not None:
            try:
                self._q.put_nowait(event)
            except queue.Full:
                pass

    def bind(self, **defaults: Any) -> "EventEmitter":
        merged = dict(self._defaults)
        merged.update({k: v for k, v in defaults.items() if v is not None})
        return EventEmitter(q=self._q, cli_mode=self._cli_mode, defaults=merged)

    def info(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("info", msg, step, **extra)

    def success(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("success", msg, step, **extra)

    def error(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("error", msg, step, **extra)

    def warn(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("warn", msg, step, **extra)


# 默认 CLI 发射器（兼容直接运行）
_cli_emitter = EventEmitter(cli_mode=True)


# ==========================================
# Mail.tm 临时邮箱 API
# ==========================================

MAILTM_BASE = "https://api.mail.tm"
DEFAULT_PROXY_POOL_URL = "https://zenproxy.top/api/fetch"
DEFAULT_PROXY_POOL_AUTH_MODE = "query"
DEFAULT_PROXY_POOL_API_KEY = "19c0ec43-8f76-4c97-81bc-bcda059eeba4"
DEFAULT_PROXY_POOL_COUNT = 1
DEFAULT_PROXY_POOL_COUNTRY = "US"
DEFAULT_HTTP_VERSION = "v2"
H3_PROXY_ERROR_HINT = "HTTP/3 is not supported over an HTTP proxy"
TRANSIENT_TLS_ERROR_HINTS = (
    "curl: (35)",
    "TLS connect error",
    "OPENSSL_internal:invalid library",
    "SSL_ERROR_SYSCALL",
)
TRANSIENT_TLS_RETRY_COUNT = 2
POOL_RELAY_RETRIES = 2
POOL_PROXY_FETCH_RETRIES = 3
POOL_RELAY_REQUEST_RETRIES = 2


def _is_transient_tls_error(exc: Exception | str) -> bool:
    message = str(exc or "")
    return any(hint in message for hint in TRANSIENT_TLS_ERROR_HINTS)


def _call_with_http_fallback(request_func, url: str, **kwargs: Any):
    """
    curl_cffi 在某些站点可能优先尝试 H3，遇到 HTTP 代理不支持时自动降级到 HTTP/1.1 重试。
    对 curl TLS 握手异常（如 curl: (35)）也进行有限重试，并优先降级到 HTTP/1.1。
    """
    try:
        return request_func(url, **kwargs)
    except Exception as exc:
        message = str(exc)
        if H3_PROXY_ERROR_HINT in message:
            retry_kwargs = dict(kwargs)
            retry_kwargs["http_version"] = "v1"
            return request_func(url, **retry_kwargs)
        if not _is_transient_tls_error(message):
            raise

        last_exc: Exception = exc
        candidate_kwargs_list = [dict(kwargs)]
        if str(kwargs.get("http_version") or "").strip().lower() != "v1":
            retry_kwargs = dict(kwargs)
            retry_kwargs["http_version"] = "v1"
            candidate_kwargs_list.append(retry_kwargs)

        for candidate_kwargs in candidate_kwargs_list:
            for attempt in range(TRANSIENT_TLS_RETRY_COUNT):
                time.sleep(min(0.35 * (attempt + 1), 1.0))
                try:
                    return request_func(url, **candidate_kwargs)
                except Exception as retry_exc:
                    last_exc = retry_exc
                    retry_message = str(retry_exc)
                    if H3_PROXY_ERROR_HINT in retry_message and str(candidate_kwargs.get("http_version") or "").strip().lower() != "v1":
                        candidate_kwargs = dict(candidate_kwargs)
                        candidate_kwargs["http_version"] = "v1"
                        continue
                    if not _is_transient_tls_error(retry_message):
                        raise
        raise last_exc

def _normalize_proxy_value(proxy_value: Any) -> str:
    value = str(proxy_value or "").strip().strip('"').strip("'")
    if not value:
        return ""
    if value.startswith("{") or value.startswith("[") or value.startswith("<"):
        return ""
    if "://" in value:
        return value
    if ":" not in value:
        return ""
    return f"http://{value}"


def _to_proxies_dict(proxy_value: str) -> Optional[Dict[str, str]]:
    normalized = _normalize_proxy_value(proxy_value)
    if not normalized:
        return None
    return {"http": normalized, "https": normalized}


def _build_proxy_from_host_port(host: Any, port: Any, proxy_type: Any = "") -> str:
    host_value = str(host or "").strip()
    port_value = str(port or "").strip()
    if not host_value or not port_value:
        return ""
    proxy_type_value = str(proxy_type or "").strip().lower()
    if proxy_type_value in ("socks5", "socks", "shadowsocks"):
        return _normalize_proxy_value(f"socks5://{host_value}:{port_value}")
    return _normalize_proxy_value(f"http://{host_value}:{port_value}")


def _pool_host_from_api_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        return str(parsed.hostname or "").strip()
    except Exception:
        return ""


def _pool_relay_url_from_fetch_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc
        if not netloc:
            return ""
        return f"{scheme}://{netloc}/api/relay"
    except Exception:
        return ""


def _trace_via_pool_relay(pool_cfg: Dict[str, Any]) -> str:
    relay_url = _pool_relay_url_from_fetch_url(str(pool_cfg.get("api_url") or ""))
    if not relay_url:
        raise RuntimeError("代理池 relay 地址解析失败")

    api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    timeout = int(pool_cfg.get("timeout_seconds") or 10)
    timeout = max(8, min(timeout, 30))

    params = {
        "api_key": api_key,
        "url": "https://cloudflare.com/cdn-cgi/trace",
        "country": country,
    }
    retry_count = max(1, int(pool_cfg.get("relay_retries") or POOL_RELAY_RETRIES))
    last_error = ""
    for i in range(retry_count):
        try:
            resp = _call_with_http_fallback(
                requests.get,
                relay_url,
                params=params,
                impersonate="chrome",
                timeout=timeout,
            )
            if resp.status_code == 200:
                return str(resp.text or "")
            last_error = f"HTTP {resp.status_code}"
        except Exception as exc:
            last_error = str(exc)
        if i < retry_count - 1:
            time.sleep(min(0.3 * (i + 1), 1.0))
    raise RuntimeError(f"代理池 relay 请求失败: {last_error or 'unknown error'}")
def _extract_proxy_from_obj(obj: Any, relay_host: str = "") -> str:
    if isinstance(obj, str):
        return _normalize_proxy_value(obj)
    if isinstance(obj, (list, tuple)):
        for item in obj:
            proxy = _extract_proxy_from_obj(item, relay_host)
            if proxy:
                return proxy
        return ""
    if isinstance(obj, dict):
        local_port = obj.get("local_port")
        if local_port in (None, ""):
            local_port = obj.get("localPort")
        if local_port not in (None, ""):
            # ZenProxy 文档中的 local_port 是代理绑定端口，优先使用 api_url 主机名。
            if relay_host:
                proxy = _normalize_proxy_value(f"http://{relay_host}:{local_port}")
                if proxy:
                    return proxy
            proxy = _normalize_proxy_value(f"http://127.0.0.1:{local_port}")
            if proxy:
                return proxy

        host = str(obj.get("ip") or obj.get("host") or obj.get("server") or "").strip()
        port = str(obj.get("port") or "").strip()
        proxy_type = obj.get("type") or obj.get("protocol") or obj.get("scheme") or ""
        if host and port:
            proxy = _build_proxy_from_host_port(host, port, proxy_type)
            if proxy:
                return proxy

        for key in ("proxy", "proxy_url", "url", "value", "result", "data", "proxy_list", "list", "proxies"):
            if key in obj:
                proxy = _extract_proxy_from_obj(obj.get(key), relay_host)
                if proxy:
                    return proxy

        for value in obj.values():
            proxy = _extract_proxy_from_obj(value, relay_host)
            if proxy:
                return proxy
    return ""


def _proxy_tcp_reachable(proxy_url: str, timeout_seconds: float = 1.2) -> bool:
    value = str(proxy_url or "").strip()
    if not value:
        return False
    if "://" not in value:
        value = "http://" + value
    try:
        parsed = urlparse(value)
        host = str(parsed.hostname or "").strip()
        port = int(parsed.port or 0)
    except Exception:
        return False
    if not host or port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def _fetch_proxy_from_pool(pool_cfg: Dict[str, Any]) -> str:
    enabled = bool(pool_cfg.get("enabled"))
    if not enabled:
        return ""

    api_url = str(pool_cfg.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL
    auth_mode = str(pool_cfg.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower()
    if auth_mode not in ("header", "query"):
        auth_mode = DEFAULT_PROXY_POOL_AUTH_MODE
    api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    relay_host = str(pool_cfg.get("relay_host") or "").strip()
    if not relay_host:
        relay_host = _pool_host_from_api_url(api_url)
    try:
        count = int(pool_cfg.get("count") or DEFAULT_PROXY_POOL_COUNT)
    except (TypeError, ValueError):
        count = DEFAULT_PROXY_POOL_COUNT
    count = max(1, min(count, 20))
    country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    timeout = int(pool_cfg.get("timeout_seconds") or 10)
    timeout = max(3, min(timeout, 30))

    headers: Dict[str, str] = {}
    params: Dict[str, str] = {"count": str(count), "country": country}
    if auth_mode == "query":
        params["api_key"] = api_key
    else:
        headers["Authorization"] = f"Bearer {api_key}"

    resp = _call_with_http_fallback(
        requests.get,
        api_url,
        headers=headers or None,
        params=params or None,
        http_version=DEFAULT_HTTP_VERSION,
        impersonate="chrome",
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"代理池请求失败: HTTP {resp.status_code}")

    proxy = ""
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            proxies = payload.get("proxies")
            if isinstance(proxies, list):
                for item in proxies:
                    proxy = _extract_proxy_from_obj(item, relay_host)
                    if proxy:
                        break
        if not proxy:
            proxy = _extract_proxy_from_obj(payload, relay_host)
    except Exception:
        proxy = ""

    if not proxy:
        proxy = _normalize_proxy_value(resp.text)
    if not proxy:
        raise RuntimeError("代理池响应中未找到可用代理")
    return proxy


def _resolve_request_proxies(
    default_proxies: Any = None,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> Any:
    if not proxy_selector:
        return default_proxies
    try:
        selected = proxy_selector()
        if selected is not None:
            return selected
    except Exception:
        pass
    return default_proxies


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailtm_domains(proxies: Any = None) -> list[str]:
    resp = _call_with_http_fallback(
        requests.get,
        f"{MAILTM_BASE}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        http_version=DEFAULT_HTTP_VERSION,
        impersonate="chrome",
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取 Mail.tm 域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


def get_email_and_token(
    proxies: Any = None,
    emitter: EventEmitter = _cli_emitter,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> tuple[str, str]:
    """创建 Mail.tm 邮箱并获取 Bearer Token"""
    try:
        domains = _mailtm_domains(_resolve_request_proxies(proxies, proxy_selector))
        if not domains:
            emitter.error("Mail.tm 没有可用域名", step="create_email")
            return "", ""
        domain = random.choice(domains)

        for _ in range(5):
            local = f"oc{secrets.token_hex(5)}"
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = _call_with_http_fallback(
                requests.post,
                f"{MAILTM_BASE}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate="chrome",
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = _call_with_http_fallback(
                requests.post,
                f"{MAILTM_BASE}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate="chrome",
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return email, token

        emitter.error("Mail.tm 邮箱创建成功但获取 Token 失败", step="create_email")
        return "", ""
    except Exception as e:
        emitter.error(f"请求 Mail.tm API 出错: {e}", step="create_email")
        return "", ""


def get_oai_code(
    token: str, email: str, proxies: Any = None, emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> str:
    """使用 Mail.tm Token 轮询获取 OpenAI 验证码"""
    url_list = f"{MAILTM_BASE}/messages"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: set[str] = set()

    emitter.info(f"正在等待邮箱 {email} 的验证码...", step="wait_otp")

    for i in range(40):
        if stop_event and stop_event.is_set():
            return ""
        try:
            resp = _call_with_http_fallback(
                requests.get,
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate="chrome",
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue

                read_resp = _call_with_http_fallback(
                    requests.get,
                    f"{MAILTM_BASE}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=_resolve_request_proxies(proxies, proxy_selector),
                    http_version=DEFAULT_HTTP_VERSION,
                    impersonate="chrome",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue
                seen_ids.add(msg_id)

                mail_data = read_resp.json()
                sender = str(
                    ((mail_data.get("from") or {}).get("address") or "")
                ).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)
                content = "\n".join([subject, intro, text, str(html)])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    emitter.success(f"验证码已到达: {m.group(1)}", step="wait_otp")
                    return m.group(1)
        except Exception:
            pass

        # 每轮等待时输出进度
        if (i + 1) % 5 == 0:
            emitter.info(f"已等待 {(i+1)*3} 秒，继续轮询...", step="wait_otp")
        time.sleep(3)

    emitter.error("超时，未收到验证码", step="wait_otp")
    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _post_form(
    url: str,
    data: Dict[str, str],
    timeout: int = 30,
    proxy: str = "",
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    handlers = []
    normalized_proxy = _normalize_proxy_value(proxy)
    if normalized_proxy:
        handlers.append(urllib.request.ProxyHandler({"http": normalized_proxy, "https": normalized_proxy}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


def _build_token_result(token_payload: Dict[str, Any], account_password: str = "") -> str:
    access_token = str(token_payload.get("access_token") or "").strip()
    refresh_token = str(token_payload.get("refresh_token") or "").strip()
    id_token = str(token_payload.get("id_token") or "").strip()
    expires_in = _to_int(token_payload.get("expires_in"))

    missing_fields = [
        name for name, value in (
            ("access_token", access_token),
            ("refresh_token", refresh_token),
            ("id_token", id_token),
        ) if not value
    ]
    if missing_fields:
        raise ValueError(f"token exchange missing fields: {', '.join(missing_fields)}")

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
    if not email or not account_id:
        raise ValueError("token exchange missing email/account_id in id_token")

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "expires_at": expired_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }
    if account_password:
        config["account_password"] = account_password
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _augment_token_payload(
    token_json: str,
    *,
    account_password: str = "",
    mail_provider_name: str = "",
    mail_credential: str = "",
) -> str:
    token_data = json.loads(token_json)
    if account_password:
        token_data["account_password"] = account_password
    if mail_provider_name:
        token_data["mail_provider"] = mail_provider_name
    if mail_credential:
        token_data["mail_credential"] = mail_credential
    return json.dumps(token_data, ensure_ascii=False, separators=(",", ":"))


def _write_text_atomic(file_path: str, content: str) -> None:
    directory = os.path.dirname(file_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, file_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    proxy: str = "",
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        proxy=proxy,
    )

    return _build_token_result(token_resp)


# ==========================================
# 核心注册逻辑
# ==========================================

from . import TOKENS_DIR as _PKG_TOKENS_DIR

TOKENS_DIR = str(_PKG_TOKENS_DIR)


def run(
    proxy: Optional[str],
    emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    mail_provider=None,
    proxy_pool_config: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    static_proxy = _normalize_proxy_value(proxy)
    static_proxies: Any = _to_proxies_dict(static_proxy)

    pool_cfg_raw = proxy_pool_config or {}
    pool_cfg = {
        "enabled": bool(pool_cfg_raw.get("enabled", False)),
        "api_url": str(pool_cfg_raw.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL,
        "auth_mode": str(pool_cfg_raw.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower() or DEFAULT_PROXY_POOL_AUTH_MODE,
        "api_key": str(pool_cfg_raw.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY,
        "count": pool_cfg_raw.get("count", DEFAULT_PROXY_POOL_COUNT),
        "country": str(pool_cfg_raw.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY,
        "timeout_seconds": int(pool_cfg_raw.get("timeout_seconds") or 10),
    }
    if pool_cfg["auth_mode"] not in ("header", "query"):
        pool_cfg["auth_mode"] = DEFAULT_PROXY_POOL_AUTH_MODE
    try:
        pool_cfg["count"] = max(1, min(int(pool_cfg.get("count") or DEFAULT_PROXY_POOL_COUNT), 20))
    except (TypeError, ValueError):
        pool_cfg["count"] = DEFAULT_PROXY_POOL_COUNT

    last_pool_proxy = ""
    pool_fail_streak = 0
    warned_fallback = False

    def _next_proxy_value() -> str:
        nonlocal last_pool_proxy, pool_fail_streak, warned_fallback
        if pool_cfg["enabled"]:
            max_fetch_retries = max(1, int(pool_cfg.get("fetch_retries") or POOL_PROXY_FETCH_RETRIES))
            last_error = ""
            for _ in range(max_fetch_retries):
                try:
                    fetched = _fetch_proxy_from_pool(pool_cfg)
                    if fetched and not _proxy_tcp_reachable(fetched):
                        last_error = f"代理池代理不可达: {fetched}"
                        continue
                    last_pool_proxy = fetched
                    pool_fail_streak = 0
                    warned_fallback = False
                    return fetched
                except Exception as e:
                    last_error = str(e)

            pool_fail_streak += 1
            if static_proxy:
                if not warned_fallback:
                    emitter.warn(f"代理池不可用，回退固定代理: {last_error or 'unknown error'}", step="check_proxy")
                    warned_fallback = True
                return static_proxy
            if pool_fail_streak <= 3:
                emitter.warn(f"代理池不可用: {last_error or 'unknown error'}", step="check_proxy")
            return ""
        return static_proxy
    def _next_proxies() -> Any:
        proxy_value = _next_proxy_value()
        return _to_proxies_dict(proxy_value)

    # 随机 Chrome 指纹，避免 OpenAI 反机器人检测
    _chrome_profiles = [
        {"major": 119, "imp": "chrome119", "build": 6045, "patch": (123, 200),
         "sec": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"'},
        {"major": 120, "imp": "chrome120", "build": 6099, "patch": (62, 200),
         "sec": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'},
        {"major": 123, "imp": "chrome123", "build": 6312, "patch": (46, 170),
         "sec": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"'},
        {"major": 124, "imp": "chrome124", "build": 6367, "patch": (60, 180),
         "sec": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'},
    ]
    _cp = random.choice(_chrome_profiles)
    _chrome_full = f"{_cp['major']}.0.{_cp['build']}.{random.randint(*_cp['patch'])}"
    _chrome_ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{_chrome_full} Safari/537.36"

    s = requests.Session(impersonate=_cp["imp"])
    s.headers.update({
        "User-Agent": _chrome_ua,
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8", "en,en-US;q=0.9"]),
        "sec-ch-ua": _cp["sec"],
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-full-version": f'"{_chrome_full}"',
        "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
    })

    def _trace_headers() -> Dict[str, str]:
        """生成 DataDog trace headers，模拟真实浏览器监控"""
        trace_id = random.randint(10**17, 10**18 - 1)
        parent_id = random.randint(10**17, 10**18 - 1)
        tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
        return {
            "traceparent": tp, "tracestate": "dd=s:1;o:rum",
            "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
        }
    pool_relay_url = _pool_relay_url_from_fetch_url(str(pool_cfg.get("api_url") or ""))
    pool_relay_enabled = bool(pool_cfg["enabled"] and pool_relay_url)
    relay_cookie_jar: Dict[str, str] = {}
    pool_relay_api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    pool_relay_country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    relay_fallback_warned = False
    relay_bypass_openai_hosts = False
    openai_relay_probe_done = False
    mail_proxy_selector = None if pool_relay_enabled else _next_proxy_value
    mail_proxies_selector = None if pool_relay_enabled else _next_proxies

    def _fallback_proxies_for_relay_failure() -> Any:
        if static_proxy:
            return _to_proxies_dict(static_proxy)
        return None

    def _target_host(target_url: str) -> str:
        return str(urlparse(str(target_url or "")).hostname or "").strip().lower()

    def _is_openai_like_host(host: str) -> bool:
        return bool(host) and (host.endswith("openai.com") or host.endswith("chatgpt.com"))

    def _should_bypass_relay_for_target(target_url: str) -> bool:
        host = _target_host(target_url)
        return relay_bypass_openai_hosts and _is_openai_like_host(host)

    def _warn_relay_fallback(reason: str, target_url: str) -> None:
        nonlocal relay_fallback_warned, relay_bypass_openai_hosts
        host = _target_host(target_url) or str(target_url or "?")
        if _is_openai_like_host(host):
            relay_bypass_openai_hosts = True
        if relay_fallback_warned:
            return
        if static_proxy:
            emitter.warn(f"代理池 relay 对 {host} 不可用，回退固定代理: {reason}", step="check_proxy")
        else:
            emitter.warn(f"代理池 relay 对 {host} 不可用，回退直连: {reason}", step="check_proxy")
        relay_fallback_warned = True

    def _update_relay_cookie_jar(resp: Any) -> None:
        try:
            for k, v in (resp.cookies or {}).items():
                key = str(k or "").strip()
                if key:
                    relay_cookie_jar[key] = str(v or "")
        except Exception:
            pass
        set_cookie_values: list[str] = []
        try:
            values = resp.headers.get_list("set-cookie")  # type: ignore[attr-defined]
            if values:
                set_cookie_values.extend(str(v or "") for v in values if str(v or "").strip())
        except Exception:
            pass
        if not set_cookie_values:
            try:
                set_cookie_raw = str(resp.headers.get("set-cookie") or "")
                if set_cookie_raw.strip():
                    set_cookie_values.append(set_cookie_raw)
            except Exception:
                pass
        for set_cookie_raw in set_cookie_values:
            try:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(set_cookie_raw)
                for k, morsel in parsed_cookie.items():
                    key = str(k or "").strip()
                    if key:
                        relay_cookie_jar[key] = str(morsel.value or "")
            except Exception:
                pass
        try:
            for k, v in relay_cookie_jar.items():
                s.cookies.set(k, v)
        except Exception:
            pass

    def _request_via_pool_relay(method: str, target_url: str, **kwargs: Any):
        if not pool_relay_enabled:
            raise RuntimeError("代理池 relay 未启用")
        relay_retries_override = kwargs.pop("_relay_retries", None)
        relay_params = {
            "api_key": pool_relay_api_key,
            "url": str(target_url),
            "method": str(method or "GET").upper(),
            "country": pool_relay_country,
        }
        target_params = kwargs.pop("params", None)
        if target_params:
            query_text = urlencode(target_params, doseq=True)
            if query_text:
                separator = "&" if "?" in relay_params["url"] else "?"
                relay_params["url"] = f"{relay_params['url']}{separator}{query_text}"

        headers = dict(kwargs.pop("headers", {}) or {})
        if relay_cookie_jar and not any(str(k).lower() == "cookie" for k in headers.keys()):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in relay_cookie_jar.items())
        kwargs.pop("proxies", None)
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 20)

        method_upper = relay_params["method"]
        retry_count = max(
            1,
            int(
                relay_retries_override
                if relay_retries_override is not None
                else (pool_cfg.get("relay_request_retries") or POOL_RELAY_REQUEST_RETRIES)
            ),
        )
        last_error = ""
        for i in range(retry_count):
            try:
                resp = _call_with_http_fallback(
                    lambda relay_endpoint, **call_kwargs: requests.request(method_upper, relay_endpoint, **call_kwargs),
                    pool_relay_url,
                    params=relay_params,
                    headers=headers or None,
                    **kwargs,
                )
                _update_relay_cookie_jar(resp)
                if resp.status_code >= 500 or resp.status_code == 429:
                    last_error = f"HTTP {resp.status_code}"
                    if i < retry_count - 1:
                        time.sleep(min(0.4 * (i + 1), 1.2))
                        continue
                return resp
            except Exception as exc:
                last_error = str(exc)
                if i < retry_count - 1:
                    time.sleep(min(0.4 * (i + 1), 1.2))
        raise RuntimeError(f"代理池 relay 请求失败: {last_error or 'unknown error'}")

    def _ensure_openai_relay_ready() -> None:
        nonlocal openai_relay_probe_done
        if not pool_relay_enabled or relay_bypass_openai_hosts or openai_relay_probe_done:
            return
        openai_relay_probe_done = True
        probe_url = "https://auth.openai.com/"
        try:
            probe_resp = _request_via_pool_relay(
                "GET",
                probe_url,
                timeout=5,
                allow_redirects=False,
                _relay_retries=1,
            )
            status = int(probe_resp.status_code or 0)
            if status < 200 or status >= 400:
                raise RuntimeError(f"HTTP {status}")
            emitter.info("代理池 relay OpenAI 预检通过", step="check_proxy")
        except Exception as exc:
            _warn_relay_fallback(f"{exc} (OpenAI 预检)", probe_url)

    def _session_get(url: str, **kwargs: Any):
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("GET", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(s.get, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(s.get, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(s.get, url, **kwargs)

    def _session_post(url: str, **kwargs: Any):
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("POST", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(s.post, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(s.post, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(s.post, url, **kwargs)

    def _raw_get(url: str, **kwargs: Any):
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("GET", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("impersonate", "chrome")
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(requests.get, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("impersonate", "chrome")
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(requests.get, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(requests.get, url, **kwargs)

    def _raw_post(url: str, **kwargs: Any):
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("POST", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("impersonate", "chrome")
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(requests.post, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("impersonate", "chrome")
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(requests.post, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(requests.post, url, **kwargs)

    def _submit_callback_url_via_pool_relay(
        *,
        callback_url: str,
        expected_state: str,
        code_verifier: str,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
    ) -> str:
        cb = _parse_callback_url(callback_url)
        if cb["error"]:
            desc = cb["error_description"]
            raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())
        if not cb["code"]:
            raise ValueError("callback url missing ?code=")
        if not cb["state"]:
            raise ValueError("callback url missing ?state=")
        if cb["state"] != expected_state:
            raise ValueError("state mismatch")

        token_resp = _request_via_pool_relay(
            "POST",
            TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=urllib.parse.urlencode(
                {
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "code": cb["code"],
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                }
            ),
            timeout=30,
        )
        if token_resp.status_code != 200:
            raise RuntimeError(
                f"token exchange failed: {token_resp.status_code}: {str(token_resp.text or '')[:240]}"
            )
        try:
            token_json = token_resp.json()
        except Exception:
            token_json = json.loads(str(token_resp.text or "{}"))

        return _augment_token_payload(
            _build_token_result(token_json, account_password=account_password),
            account_password=account_password,
            mail_provider_name=mail_provider_name,
            mail_credential=dev_token,
        )

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    try:
        # ------- 步骤1：网络环境检查 -------
        emitter.info("正在检查网络环境...", step="check_proxy")
        try:
            trace_text = ""
            relay_error = ""
            relay_used = False
            if pool_cfg["enabled"]:
                try:
                    trace_text = _trace_via_pool_relay(pool_cfg)
                    relay_used = True
                except Exception as e:
                    relay_error = str(e)
                    if static_proxy:
                        emitter.warn(f"代理池 relay 检查失败，回退固定代理: {relay_error}", step="check_proxy")
                    else:
                        emitter.warn(f"代理池 relay 检查失败，尝试直连代理: {relay_error}", step="check_proxy")
            if not trace_text:
                trace_resp = _session_get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
                trace_text = trace_resp.text
            trace = trace_text
            loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
            loc = loc_re.group(1) if loc_re else None
            ip_re = re.search(r"^ip=(.+)$", trace, re.MULTILINE)
            current_ip = ip_re.group(1).strip() if ip_re else ""
            if relay_used:
                emitter.info("代理池 relay 连通检查成功", step="check_proxy")
            emitter.info(f"当前 IP 所在地: {loc}", step="check_proxy")
            if current_ip:
                emitter.info(f"当前出口 IP: {current_ip}", step="check_proxy")
            if loc == "CN" or loc == "HK":
                emitter.error("检查代理哦 — 所在地不支持 (CN/HK)", step="check_proxy")
                return None
            emitter.success("网络环境检查通过", step="check_proxy")
            _ensure_openai_relay_ready()
        except Exception as e:
            emitter.error(f"网络连接检查失败: {e}", step="check_proxy")
            return None

        if _stopped():
            return None

        # ------- 步骤2：创建临时邮箱 -------
        if mail_provider is not None:
            emitter.info("正在创建临时邮箱...", step="create_email")
            mail_provider_name = str(
                getattr(mail_provider, "provider_name", "")
                or getattr(mail_provider, "name", "")
                or emitter._defaults.get("mail_provider")
                or ""
            ).strip()
            try:
                email, dev_token = mail_provider.create_mailbox(
                    proxy=static_proxy,
                    proxy_selector=mail_proxy_selector,
                )
            except TypeError:
                email, dev_token = mail_provider.create_mailbox(proxy=static_proxy)
        else:
            emitter.info("正在创建 Mail.tm 临时邮箱...", step="create_email")
            mail_provider_name = "mailtm"
            email, dev_token = get_email_and_token(
                static_proxies,
                emitter,
                proxy_selector=mail_proxies_selector,
            )
        if not email or not dev_token:
            emitter.error("临时邮箱创建失败", step="create_email")
            return None
        emitter.success(f"临时邮箱创建成功: {email}", step="create_email")

        # 生成随机密码（密码注册流程需要）
        _pw_chars = string.ascii_letters + string.digits + "!@#$%&*"
        account_password = "".join(secrets.choice(_pw_chars) for _ in range(16))

        if _stopped():
            return None

        # ------- 步骤3：通过 chatgpt.com 建立注册会话 -------
        emitter.info("正在访问 ChatGPT 首页...", step="oauth_init")
        _chatgpt_base = "https://chatgpt.com"

        # 3a: 访问首页，获取 cookies
        _session_get(f"{_chatgpt_base}/", timeout=20)

        # 3b: 获取 CSRF Token
        csrf_resp = _session_get(
            f"{_chatgpt_base}/api/auth/csrf",
            headers={"Accept": "application/json", "Referer": f"{_chatgpt_base}/"},
            timeout=15,
        )

        try:
            csrf_token = csrf_resp.json().get("csrfToken", "")
        except Exception as e:
            csrf_token = ""
            emitter.error("获取 CSRF Token 失败" + str(e), step="oauth_init")
        if not csrf_token:
            emitter.error("获取 CSRF Token 失败", step="oauth_init")
            return None

        # 3c: 生成 Device ID
        did = s.cookies.get("oai-did") or relay_cookie_jar.get("oai-did") or ""
        if not did:
            did = str(uuid.uuid4())
            relay_cookie_jar["oai-did"] = did
            try:
                s.cookies.set("oai-did", did, domain="chatgpt.com")
            except Exception:
                try:
                    s.cookies.set("oai-did", did)
                except Exception:
                    pass

        # 3d: Signin 请求，获取 authorize URL
        auth_session_id = str(uuid.uuid4())
        signin_params = urllib.parse.urlencode({
            "prompt": "login",
            "ext-oai-did": did,
            "auth_session_logging_id": auth_session_id,
            "screen_hint": "login_or_signup",
            "login_hint": email,
        })
        signin_resp = _session_post(
            f"{_chatgpt_base}/api/auth/signin/openai?{signin_params}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Referer": f"{_chatgpt_base}/",
                "Origin": _chatgpt_base,
            },
            data=urllib.parse.urlencode({
                "callbackUrl": f"{_chatgpt_base}/",
                "csrfToken": csrf_token,
                "json": "true",
            }),
            timeout=20,
        )
        try:
            authorize_url = signin_resp.json().get("url", "")
        except Exception:
            authorize_url = ""
        if not authorize_url:
            emitter.error(
                f"Signin 获取授权链接失败（{signin_resp.status_code}）: {str(signin_resp.text or '')[:220]}",
                step="oauth_init",
            )
            return None
        emitter.info(f"OAuth 初始化状态: {signin_resp.status_code}", step="oauth_init")

        # 3e: 跟随 authorize 重定向，建立 auth.openai.com 会话
        auth_resp = _session_get(
            authorize_url,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{_chatgpt_base}/",
                "Upgrade-Insecure-Requests": "1",
            },
            timeout=20,
        )
        final_url = str(auth_resp.url) if hasattr(auth_resp, "url") else ""
        emitter.info(f"Authorize 重定向完成: {final_url[:120]}", step="oauth_init")
        emitter.info(f"Device ID: {did}", step="oauth_init")

        if _stopped():
            return None

        # ------- 步骤4+5：密码注册（合并旧步骤4 Sentinel + 旧步骤5 注册） -------
        time.sleep(random.uniform(0.5, 1.0))
        emitter.info("正在提交注册表单（密码模式）...", step="signup")
        _reg_headers = {
            "referer": "https://auth.openai.com/create-account/password",
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://auth.openai.com",
        }
        _reg_headers.update(_trace_headers())
        signup_resp = _session_post(
            "https://auth.openai.com/api/accounts/user/register",
            headers=_reg_headers,
            json={"username": email, "password": account_password},
        )
        emitter.info(f"注册表单提交状态: {signup_resp.status_code}", step="signup")
        if signup_resp.status_code != 200:
            emitter.error(
                f"注册表单提交失败（状态码 {signup_resp.status_code}）: {str(signup_resp.text or '')[:220]}",
                step="signup",
            )
            return None

        # ------- 步骤6：发送 OTP 验证码 -------
        time.sleep(random.uniform(0.3, 0.8))
        emitter.info("正在发送邮箱验证码...", step="send_otp")
        otp_resp = _session_get(
            "https://auth.openai.com/api/accounts/email-otp/send",
            headers={
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "upgrade-insecure-requests": "1",
            },
        )
        emitter.info(f"验证码发送状态: {otp_resp.status_code}", step="send_otp")
        if otp_resp.status_code == 409:
            emitter.warn(f"send_otp 409 响应: {str(otp_resp.text or '')[:220]}", step="send_otp")

        if otp_resp.status_code != 200:
            emitter.error(f"验证码发送失败（状态码 {otp_resp.status_code}）: {str(otp_resp.text or '')[:220]}", step="send_otp")
            return None

        if _stopped():
            return None

        # ------- 步骤7：轮询邮箱拿验证码 -------
        if mail_provider is not None:
            try:
                code = mail_provider.wait_for_otp(
                    dev_token,
                    email,
                    proxy=static_proxy,
                    proxy_selector=mail_proxy_selector,
                    stop_event=stop_event,
                )
            except TypeError:
                code = mail_provider.wait_for_otp(
                    dev_token,
                    email,
                    proxy=static_proxy,
                    stop_event=stop_event,
                )
        else:
            code = get_oai_code(
                dev_token,
                email,
                static_proxies,
                emitter,
                stop_event,
                proxy_selector=mail_proxies_selector,
            )
        if not code:
            return None

        if _stopped():
            return None

        # ------- 步骤8：提交验证码 -------
        time.sleep(random.uniform(0.3, 0.8))
        emitter.info("正在验证 OTP...", step="verify_otp")
        _otp_headers = {
            "referer": "https://auth.openai.com/email-verification",
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://auth.openai.com",
        }
        _otp_headers.update(_trace_headers())
        code_resp = _session_post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            headers=_otp_headers,
            json={"code": code},
        )
        emitter.info(f"验证码校验状态: {code_resp.status_code}", step="verify_otp")
        if code_resp.status_code != 200:
            emitter.error(
                f"验证码校验失败（状态码 {code_resp.status_code}）: {str(code_resp.text or '')[:220]}",
                step="verify_otp",
            )
            return None

        if _stopped():
            return None

        # ------- 步骤9：创建账户 -------
        time.sleep(random.uniform(0.5, 1.5))
        emitter.info("正在创建账户信息...", step="create_account")
        _rand_first = random.choice([
            "James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Sophia",
            "Lucas", "Mia", "Mason", "Isabella", "Logan", "Charlotte", "Alexander",
            "Amelia", "Benjamin", "Harper", "William", "Evelyn", "Henry", "Abigail",
        ])
        _rand_last = random.choice([
            "Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Taylor",
            "Clark", "Hall", "Young", "Anderson", "Thomas", "Jackson", "White",
        ])
        _rand_name = f"{_rand_first} {_rand_last}"
        _rand_bday = f"{random.randint(1985, 2002)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        _ca_headers = {
            "referer": "https://auth.openai.com/about-you",
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://auth.openai.com",
        }
        _ca_headers.update(_trace_headers())
        create_account_resp = _session_post(
            "https://auth.openai.com/api/accounts/create_account",
            headers=_ca_headers,
            json={"name": _rand_name, "birthdate": _rand_bday},
        )
        create_account_status = create_account_resp.status_code
        emitter.info(f"账户创建状态: {create_account_status}", step="create_account")

        if create_account_status != 200:
            emitter.error(create_account_resp.text, step="create_account")
            return None

        emitter.success("账户创建成功！", step="create_account")

        # 跟随 callback URL 完成注册流程
        try:
            _ca_data = create_account_resp.json() if create_account_resp.text else {}
        except Exception:
            _ca_data = {}
        _callback_url = (
            _ca_data.get("continue_url")
            or _ca_data.get("url")
            or _ca_data.get("redirect_url")
            or ""
        )
        if _callback_url:
            emitter.info("正在完成注册回调...", step="create_account")
            _session_get(
                _callback_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                },
                timeout=20,
            )

        if _stopped():
            return None

        # ------- 步骤10+11：完整 OAuth 登录流程获取 Token -------
        emitter.info("正在通过 OAuth 登录获取 Token...", step="get_token")

        # 确保 auth 域也有 oai-did cookie
        try:
            s.cookies.set("oai-did", did, domain=".auth.openai.com")
            s.cookies.set("oai-did", did, domain="auth.openai.com")
        except Exception:
            pass

        # 10a: 生成 PKCE 参数和 authorize URL
        oauth = generate_oauth_url()

        # 10b: Sentinel PoW token 生成器（纯 Python）
        class _SentinelGen:
            MAX_ATTEMPTS = 500000
            ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
            def __init__(self, dev_id, ua):
                self.dev_id = dev_id
                self.ua = ua
                self.req_seed = str(random.random())
                self.sid = str(uuid.uuid4())
            @staticmethod
            def _fnv1a(text):
                h = 2166136261
                for ch in text:
                    h ^= ord(ch); h = (h * 16777619) & 0xFFFFFFFF
                h ^= (h >> 16); h = (h * 2246822507) & 0xFFFFFFFF
                h ^= (h >> 13); h = (h * 3266489909) & 0xFFFFFFFF
                h ^= (h >> 16); return format(h & 0xFFFFFFFF, "08x")
            def _cfg(self):
                now_s = time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime())
                perf = random.uniform(1000, 50000)
                return ["1920x1080", now_s, 4294705152, random.random(), self.ua,
                        "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
                        None, None, "en-US", "en-US,en", random.random(),
                        random.choice(["vendorSub","productSub","hardwareConcurrency","cookieEnabled"]) + "-undefined",
                        random.choice(["location","URL","compatMode"]),
                        random.choice(["Object","Function","Array","Number"]),
                        perf, self.sid, "", random.choice([4,8,12,16]), time.time()*1000 - perf]
            @staticmethod
            def _b64(data):
                return base64.b64encode(json.dumps(data, separators=(",",":")).encode()).decode()
            def _solve(self, seed, diff, cfg, nonce):
                cfg[3] = nonce; cfg[9] = round((time.time() - self._t0) * 1000)
                d = self._b64(cfg); h = self._fnv1a(seed + d)
                return (d + "~S") if h[:len(diff)] <= diff else None
            def gen_token(self, seed=None, diff="0"):
                seed = seed or self.req_seed; self._t0 = time.time(); cfg = self._cfg()
                for i in range(self.MAX_ATTEMPTS):
                    r = self._solve(seed, str(diff), cfg, i)
                    if r: return "gAAAAAB" + r
                return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))
            def gen_req_token(self):
                cfg = self._cfg(); cfg[3] = 1; cfg[9] = round(random.uniform(5, 50))
                return "gAAAAAC" + self._b64(cfg)

        _sentinel = _SentinelGen(did, _chrome_ua)

        def _build_sentinel(flow):
            req_body = json.dumps({"p": _sentinel.gen_req_token(), "id": did, "flow": flow})
            sen_resp = _session_post(
                "https://sentinel.openai.com/backend-api/sentinel/req",
                headers={
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Origin": "https://sentinel.openai.com",
                    "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
                },
                data=req_body,
            )
            if sen_resp.status_code != 200:
                return None
            try:
                ch = sen_resp.json()
            except Exception:
                return None
            c_val = ch.get("token", "")
            if not c_val:
                return None
            pow_d = ch.get("proofofwork") or {}
            if pow_d.get("required") and pow_d.get("seed"):
                p_val = _sentinel.gen_token(seed=pow_d["seed"], diff=pow_d.get("difficulty", "0"))
            else:
                p_val = _sentinel.gen_req_token()
            return json.dumps({"p": p_val, "t": "", "c": c_val, "id": did, "flow": flow}, separators=(",",":"))

        def _oauth_headers(referer):
            h = {"Accept": "application/json", "Content-Type": "application/json",
                 "Origin": "https://auth.openai.com", "Referer": referer, "oai-device-id": did}
            h.update(_trace_headers())
            return h

        # 10c: GET /oauth/authorize — 建立 OAuth 会话
        emitter.info("OAuth 1/5: 初始化授权...", step="get_token")
        _session_get(oauth.auth_url, timeout=30)

        if _stopped():
            return None

        # 10d: POST authorize/continue — 提交邮箱
        emitter.info("OAuth 2/5: 提交邮箱...", step="get_token")
        _sen_ac = _build_sentinel("authorize_continue")
        if not _sen_ac:
            emitter.error("Sentinel token (authorize_continue) 获取失败", step="get_token")
            return None
        _ac_headers = _oauth_headers("https://auth.openai.com/log-in")
        _ac_headers["openai-sentinel-token"] = _sen_ac
        _ac_resp = _session_post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=_ac_headers,
            json={"username": {"kind": "email", "value": email}},
        )
        emitter.info(f"authorize/continue -> {_ac_resp.status_code}", step="get_token")
        if _ac_resp.status_code != 200:
            emitter.error(f"authorize/continue 失败: {str(_ac_resp.text or '')[:200]}", step="get_token")
            return None

        if _stopped():
            return None

        # 10e: POST password/verify — 提交密码
        emitter.info("OAuth 3/5: 验证密码...", step="get_token")
        _sen_pw = _build_sentinel("password_verify")
        if not _sen_pw:
            emitter.error("Sentinel token (password_verify) 获取失败", step="get_token")
            return None
        _pw_headers = _oauth_headers("https://auth.openai.com/log-in/password")
        _pw_headers["openai-sentinel-token"] = _sen_pw
        _pw_resp = _session_post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=_pw_headers,
            json={"password": account_password},
        )
        emitter.info(f"password/verify -> {_pw_resp.status_code}", step="get_token")
        if _pw_resp.status_code != 200:
            emitter.error(f"password/verify 失败: {str(_pw_resp.text or '')[:200]}", step="get_token")
            return None

        try:
            _pw_data = _pw_resp.json()
        except Exception:
            _pw_data = {}
        _consent_url = str(_pw_data.get("continue_url") or "").strip()
        _page_type = str((_pw_data.get("page") or {}).get("type", "")).strip()
        emitter.info(f"password/verify page={_page_type or '-'} next={(_consent_url or '-')[:140]}", step="get_token")

        # OAuth 阶段可能需要第二次邮箱 OTP 验证
        _need_oauth_otp = (
            _page_type == "email_otp_verification"
            or "email-verification" in (_consent_url or "")
            or "email-otp" in (_consent_url or "")
        )
        if _need_oauth_otp:
            emitter.info("OAuth 需要邮箱 OTP 验证...", step="get_token")
            if not dev_token or mail_provider is None:
                emitter.error("OAuth OTP 验证需要邮箱 token，但不可用", step="get_token")
                return None

            _otp_ok = False
            _otp_deadline = time.time() + 120
            _tried_codes: set = set()
            while time.time() < _otp_deadline and not _otp_ok:
                if _stopped():
                    return None
                try:
                    _otp_code2 = mail_provider.wait_for_otp(
                        dev_token, email, proxy=static_proxy,
                        proxy_selector=mail_proxy_selector, stop_event=stop_event,
                    )
                except TypeError:
                    _otp_code2 = mail_provider.wait_for_otp(
                        dev_token, email, proxy=static_proxy, stop_event=stop_event,
                    )
                if not _otp_code2 or _otp_code2 in _tried_codes:
                    time.sleep(2)
                    continue
                _tried_codes.add(_otp_code2)
                emitter.info(f"OAuth OTP 尝试: {_otp_code2}", step="get_token")
                _otp2_h = _oauth_headers("https://auth.openai.com/email-verification")
                _otp2_resp = _session_post(
                    "https://auth.openai.com/api/accounts/email-otp/validate",
                    headers=_otp2_h,
                    json={"code": _otp_code2},
                )
                emitter.info(f"OAuth OTP validate -> {_otp2_resp.status_code}", step="get_token")
                if _otp2_resp.status_code == 200:
                    try:
                        _otp2_data = _otp2_resp.json()
                    except Exception:
                        _otp2_data = {}
                    _consent_url = str(_otp2_data.get("continue_url") or "").strip() or _consent_url
                    _page_type = str((_otp2_data.get("page") or {}).get("type", "")).strip() or _page_type
                    emitter.info(f"OAuth OTP 验证通过 page={_page_type or '-'} next={(_consent_url or '-')[:140]}", step="get_token")
                    _otp_ok = True
                    break
                time.sleep(2)

            if not _otp_ok:
                emitter.error(f"OAuth OTP 验证失败，已尝试 {len(_tried_codes)} 个验证码", step="get_token")
                return None

        if _stopped():
            return None

        # 10f: Workspace/consent/org 处理 + 提取 code（对标参考代码）
        _AUTH = "https://auth.openai.com"

        def _extract_code(url):
            if not url or "code=" not in url:
                return None
            try:
                return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]
            except Exception:
                return None

        def _follow_for_code(start_url):
            """手动跟随重定向链，逐步检查 Location 中是否含 code"""
            url = start_url
            for _ in range(12):
                try:
                    r = _session_get(url, allow_redirects=False, timeout=15)
                except Exception as e:
                    # curl_cffi 连接 localhost 会抛异常，URL 可能在异常信息中
                    m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                    if m:
                        return _extract_code(m.group(1))
                    return None
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if not loc:
                        break
                    next_url = urllib.parse.urljoin(url, loc)
                    c = _extract_code(next_url)
                    if c:
                        return c
                    url = next_url
                    continue
                break
            return None

        def _ws_org_select(consent_ref):
            """完整的 workspace + organization 选择流程"""
            # 解析 session cookie 获取 workspace
            _ck_data = None
            _auth_ck = s.cookies.get("oai-client-auth-session") or relay_cookie_jar.get("oai-client-auth-session") or ""
            if _auth_ck:
                try:
                    _ck_data = _decode_jwt_segment(_auth_ck.split(".")[0])
                except Exception:
                    pass
            if not _ck_data:
                emitter.info("无法解码 auth session cookie", step="workspace")
                return None

            _ws_list = _ck_data.get("workspaces") or []
            _ws_id = str((_ws_list[0] or {}).get("id") or "").strip() if _ws_list else ""
            if not _ws_id:
                emitter.info("session 中没有 workspace", step="workspace")
                return None

            emitter.info(f"选择 workspace: {_ws_id}", step="workspace")
            _ws_h = _oauth_headers(consent_ref)
            _ws_resp = _session_post(
                f"{_AUTH}/api/accounts/workspace/select",
                headers=_ws_h,
                json={"workspace_id": _ws_id},
                allow_redirects=False,
            )
            emitter.info(f"workspace/select -> {_ws_resp.status_code}", step="workspace")

            # 如果是重定向，直接提取 code
            if _ws_resp.status_code in (301, 302, 303, 307, 308):
                loc = _ws_resp.headers.get("Location", "")
                if loc.startswith("/"):
                    loc = f"{_AUTH}{loc}"
                c = _extract_code(loc)
                if c:
                    return c
                return _follow_for_code(loc)

            if _ws_resp.status_code != 200:
                return None

            try:
                _ws_data = _ws_resp.json()
            except Exception:
                return None

            _ws_next = str(_ws_data.get("continue_url") or "").strip()
            _ws_page = str((_ws_data.get("page") or {}).get("type", ""))
            _orgs = (_ws_data.get("data") or {}).get("orgs") or []
            emitter.info(f"workspace/select page={_ws_page or '-'} orgs={len(_orgs)} next={(_ws_next or '-')[:140]}", step="workspace")

            # Organization 选择
            if _orgs:
                _org_id = (_orgs[0] or {}).get("id")
                _projects = (_orgs[0] or {}).get("projects") or []
                _proj_id = (_projects[0] or {}).get("id") if _projects else None
                if _org_id:
                    _org_body = {"org_id": _org_id}
                    if _proj_id:
                        _org_body["project_id"] = _proj_id
                    _org_ref = _ws_next if _ws_next and _ws_next.startswith("http") else f"{_AUTH}{_ws_next}" if _ws_next else consent_ref
                    _org_h = _oauth_headers(_org_ref)
                    emitter.info(f"选择 organization: {_org_id}", step="workspace")
                    _org_resp = _session_post(
                        f"{_AUTH}/api/accounts/organization/select",
                        headers=_org_h,
                        json=_org_body,
                        allow_redirects=False,
                    )
                    emitter.info(f"organization/select -> {_org_resp.status_code}", step="workspace")

                    if _org_resp.status_code in (301, 302, 303, 307, 308):
                        loc = _org_resp.headers.get("Location", "")
                        if loc.startswith("/"):
                            loc = f"{_AUTH}{loc}"
                        c = _extract_code(loc)
                        if c:
                            return c
                        return _follow_for_code(loc)

                    if _org_resp.status_code == 200:
                        try:
                            _org_data = _org_resp.json()
                        except Exception:
                            _org_data = {}
                        _org_next = str(_org_data.get("continue_url") or "").strip()
                        if _org_next:
                            if _org_next.startswith("/"):
                                _org_next = f"{_AUTH}{_org_next}"
                            c = _extract_code(_org_next)
                            if c:
                                return c
                            return _follow_for_code(_org_next)

            # 无 org 或 org 选择后仍无 code，跟随 ws_next
            if _ws_next:
                if _ws_next.startswith("/"):
                    _ws_next = f"{_AUTH}{_ws_next}"
                c = _extract_code(_ws_next)
                if c:
                    return c
                return _follow_for_code(_ws_next)

            return None

        _code = None

        # 规范化 consent_url
        if _consent_url and _consent_url.startswith("/"):
            _consent_url = f"{_AUTH}{_consent_url}"
        if not _consent_url and "consent" in _page_type:
            _consent_url = f"{_AUTH}/sign-in-with-chatgpt/codex/consent"

        # 先从 URL 直接提取
        if _consent_url:
            _code = _extract_code(_consent_url)

        # 跟随 consent_url 重定向
        if not _code and _consent_url:
            emitter.info("OAuth 4/5: 跟随 consent URL...", step="get_token")
            _code = _follow_for_code(_consent_url)

        # workspace + organization 选择
        _consent_hint = any(kw in (_consent_url or "") for kw in ["consent", "workspace", "organization", "sign-in-with"])
        _consent_hint = _consent_hint or any(kw in _page_type for kw in ["consent", "organization"])
        if not _code and (_consent_hint or not _consent_url):
            emitter.info("OAuth 4/5: 处理 workspace/org...", step="workspace")
            _ws_ref = _consent_url or f"{_AUTH}/sign-in-with-chatgpt/codex/consent"
            _code = _ws_org_select(_ws_ref)

        # 回退
        if not _code:
            emitter.info("OAuth 4/5: 回退 consent 路径...", step="get_token")
            _code = _ws_org_select(f"{_AUTH}/sign-in-with-chatgpt/codex/consent")
            if not _code:
                _code = _follow_for_code(f"{_AUTH}/sign-in-with-chatgpt/codex/consent")

        if not _code:
            emitter.error("未能获取 OAuth authorization code", step="get_token")
            try: s.close()
            except: pass
            return None

        # 10g: POST /oauth/token — 用 code 换取 Token
        emitter.info("OAuth 5/5: 交换 Token...", step="get_token")
        _token_resp = _session_post(
            TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data=urllib.parse.urlencode({
                "grant_type": "authorization_code",
                "code": _code,
                "redirect_uri": oauth.redirect_uri,
                "client_id": CLIENT_ID,
                "code_verifier": oauth.code_verifier,
            }),
            timeout=30,
        )
        if _token_resp.status_code != 200:
            emitter.error(f"Token 交换失败({_token_resp.status_code}): {str(_token_resp.text or '')[:200]}", step="get_token")
            try: s.close()
            except: pass
            return None

        try:
            _token_json = _token_resp.json()
        except Exception:
            _token_json = json.loads(str(_token_resp.text or "{}"))

        emitter.success("Token 获取成功！", step="get_token")
        try: s.close()
        except: pass
        return _augment_token_payload(
            _build_token_result(_token_json, account_password=account_password),
            account_password=account_password,
            mail_provider_name=mail_provider_name,
            mail_credential=dev_token,
        )

    except Exception as e:
        emitter.error(f"运行时发生错误: {e}", step="runtime")
        try: s.close()
        except: pass
        return None

# ==========================================
# CLI 入口（兼容直接运行）
# ==========================================


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI 账号池编排器脚本")
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7897"
    )
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="循环模式最长等待秒数"
    )
    args = parser.parse_args()

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)

    os.makedirs(TOKENS_DIR, exist_ok=True)

    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "sync_config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            sync_cfg = json.load(f)
    except Exception:
        sync_cfg = {}

    cpa_base_url = str(sync_cfg.get("cpa_base_url") or "").strip()
    cpa_token = str(sync_cfg.get("cpa_token") or "").strip()
    
    pool_maintainer = None
    if cpa_base_url and cpa_token:
        try:
            from .pool_maintainer import PoolMaintainer
            pool_maintainer = PoolMaintainer(
                cpa_base_url=cpa_base_url,
                cpa_token=cpa_token,
            )
        except Exception as e:
            print(f"[-] 初始化 PoolMaintainer 失败: {e}")

    count = 0
    print("[Info] OpenAI 账号池编排器 - CLI 模式")

    while True:
        count += 1
        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<"
        )

        try:
            token_json = run(args.proxy)

            if token_json:
                try:
                    t_data = json.loads(token_json)
                    fname_email = t_data.get("email", "unknown").replace("@", "_")
                except Exception:
                    fname_email = "unknown"
                    t_data = {}

                file_name = f"token_{fname_email}_{time.time_ns()}.json"
                file_path = os.path.join(TOKENS_DIR, file_name)

                _write_text_atomic(file_path, token_json)

                print(f"[*] 成功! Token 已保存至: {file_path}")

                if pool_maintainer and t_data:
                    print(f"[*] 正在尝试上传到 CPA...")
                    try:
                        cpa_ok = pool_maintainer.upload_token(file_name, t_data, proxy=args.proxy or "")
                        upload_email = t_data.get('email', fname_email)
                        if cpa_ok:
                            print(f"[+] CPA 上传成功: {upload_email}")
                        else:
                            print(f"[-] CPA 上传失败: {upload_email}")
                    except Exception as e:
                        print(f"[-] CPA 上传抛出异常: {e}")
            else:
                print("[-] 本次注册失败。")

        except Exception as e:
            print(f"[Error] 发生未捕获异常: {e}")

        if args.once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        print(f"[*] 休息 {wait_time} 秒...")
        time.sleep(wait_time)


if __name__ == "__main__":
    main()

