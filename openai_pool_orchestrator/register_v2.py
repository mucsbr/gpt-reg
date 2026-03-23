"""
新版注册引擎 - 双会话模式

核心改动：
1. create_account 接口新增 Sentinel PoW 验证
2. 注册完成后丢弃整个 session，用全新会话走登录拿 token（绕过 add-phone）
3. 登录阶段 password/verify 后不再手动调 email-otp/send（服务器自动发）
"""

import json
import os
import re
import sys
import time
import uuid
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
import queue
from http.cookies import SimpleCookie
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote, urljoin

from curl_cffi import requests

# 从 register.py 导入可复用的函数和常量
from .register import (
    EventEmitter,
    _call_with_http_fallback,
    _normalize_proxy_value,
    _to_proxies_dict,
    _fetch_proxy_from_pool,
    _proxy_tcp_reachable,
    _build_token_result,
    _write_text_atomic,
    _jwt_claims_no_verify,
    _decode_jwt_segment,
    generate_oauth_url,
    get_email_and_token,
    get_oai_code,
    _trace_via_pool_relay,
    _pool_relay_url_from_fetch_url,
    AUTH_URL,
    TOKEN_URL,
    CLIENT_ID,
    DEFAULT_REDIRECT_URI,
    DEFAULT_SCOPE,
    DEFAULT_PROXY_POOL_URL,
    DEFAULT_PROXY_POOL_AUTH_MODE,
    DEFAULT_PROXY_POOL_API_KEY,
    DEFAULT_PROXY_POOL_COUNT,
    DEFAULT_PROXY_POOL_COUNTRY,
    DEFAULT_HTTP_VERSION,
    POOL_PROXY_FETCH_RETRIES,
    POOL_RELAY_REQUEST_RETRIES,
    TOKENS_DIR,
)

_cli_emitter = EventEmitter(cli_mode=True)


# ==========================================
# Chrome 指纹配置
# ==========================================

_CHROME_PROFILES = [
    {"major": 119, "imp": "chrome119", "build": 6045, "patch": (123, 200),
     "sec": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"'},
    {"major": 120, "imp": "chrome120", "build": 6099, "patch": (62, 200),
     "sec": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'},
    {"major": 123, "imp": "chrome123", "build": 6312, "patch": (46, 170),
     "sec": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"'},
    {"major": 124, "imp": "chrome124", "build": 6367, "patch": (60, 180),
     "sec": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'},
]


def _make_chrome_fingerprint():
    """生成随机 Chrome 指纹"""
    cp = random.choice(_CHROME_PROFILES)
    full = f"{cp['major']}.0.{cp['build']}.{random.randint(*cp['patch'])}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full} Safari/537.36"
    return cp, full, ua


def _make_session(cp, full, ua):
    """创建新的 curl_cffi session"""
    s = requests.Session(impersonate=cp["imp"])
    s.headers.update({
        "User-Agent": ua,
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8", "en,en-US;q=0.9"]),
        "sec-ch-ua": cp["sec"],
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-full-version": f'"{full}"',
        "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
    })
    return s


# ==========================================
# Sentinel PoW Token 生成器
# ==========================================

class SentinelGen:
    """Sentinel PoW token 生成器（纯 Python）"""
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
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        return format(h & 0xFFFFFFFF, "08x")

    def _cfg(self):
        now_s = time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime())
        perf = random.uniform(1000, 50000)
        return [
            "1920x1080", now_s, 4294705152, random.random(), self.ua,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None, None, "en-US", "en-US,en", random.random(),
            random.choice(["vendorSub", "productSub", "hardwareConcurrency", "cookieEnabled"]) + "-undefined",
            random.choice(["location", "URL", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number"]),
            perf, self.sid, "", random.choice([4, 8, 12, 16]), time.time() * 1000 - perf,
        ]

    @staticmethod
    def _b64(data):
        return base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()

    def _solve(self, seed, diff, cfg, nonce):
        cfg[3] = nonce
        cfg[9] = round((time.time() - self._t0) * 1000)
        d = self._b64(cfg)
        h = self._fnv1a(seed + d)
        return (d + "~S") if h[:len(diff)] <= diff else None

    def gen_token(self, seed=None, diff="0"):
        seed = seed or self.req_seed
        self._t0 = time.time()
        cfg = self._cfg()
        for i in range(self.MAX_ATTEMPTS):
            r = self._solve(seed, str(diff), cfg, i)
            if r:
                return "gAAAAAB" + r
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))

    def gen_req_token(self):
        cfg = self._cfg()
        cfg[3] = 1
        cfg[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(cfg)


# ==========================================
# 浏览器请求头（模拟 Chrome 145）
# ==========================================

BROWSER_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

# ==========================================
# 核心注册 + 登录流程（双会话模式）
# ==========================================

def run_v2(
    proxy: Optional[str],
    emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    mail_provider=None,
    proxy_pool_config: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    双会话注册流程：
    - 第一阶段：注册会话，走到 create_account 返回 200 就停
    - 第二阶段：全新会话走登录流程拿 token
    """
    static_proxy = _normalize_proxy_value(proxy)
    static_proxies: Any = _to_proxies_dict(static_proxy)

    # 代理池配置
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

    def _update_relay_cookie_jar(resp: Any, session: Any) -> None:
        try:
            for k, v in (resp.cookies or {}).items():
                key = str(k or "").strip()
                if key:
                    relay_cookie_jar[key] = str(v or "")
        except Exception:
            pass
        set_cookie_values: list[str] = []
        try:
            values = resp.headers.get_list("set-cookie")
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
                session.cookies.set(k, v)
        except Exception:
            pass

    def _request_via_pool_relay(method: str, target_url: str, session: Any = None, **kwargs: Any):
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
                if session is not None:
                    _update_relay_cookie_jar(resp, session)
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
            probe_resp = _request_via_pool_relay("GET", probe_url, timeout=5, allow_redirects=False, _relay_retries=1)
            status = int(probe_resp.status_code or 0)
            if status < 200 or status >= 400:
                raise RuntimeError(f"HTTP {status}")
            emitter.info("代理池 relay OpenAI 预检通过", step="check_proxy")
        except Exception as exc:
            _warn_relay_fallback(f"{exc} (OpenAI 预检)", probe_url)

    def _make_session_helpers(s):
        """为给定 session 创建 _session_get / _session_post 闭包"""

        def _session_get(url: str, **kwargs: Any):
            if pool_relay_enabled and not _should_bypass_relay_for_target(url):
                try:
                    relay_resp = _request_via_pool_relay("GET", url, session=s, **kwargs)
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
                    relay_resp = _request_via_pool_relay("POST", url, session=s, **kwargs)
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

        return _session_get, _session_post

    def _trace_headers() -> Dict[str, str]:
        trace_id = random.randint(10**17, 10**18 - 1)
        parent_id = random.randint(10**17, 10**18 - 1)
        tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
        return {
            "traceparent": tp, "tracestate": "dd=s:1;o:rum",
            "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
        }

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    # ============================
    # 第一阶段：注册
    # ============================

    # 创建注册用的 session
    cp1, full1, ua1 = _make_chrome_fingerprint()
    s1 = _make_session(cp1, full1, ua1)
    session_get, session_post = _make_session_helpers(s1)

    try:
        # ------- 步骤1：网络环境检查 -------
        emitter.info("正在检查网络环境...", step="check_proxy")
        try:
            trace_text = ""
            relay_used = False
            if pool_cfg["enabled"]:
                try:
                    trace_text = _trace_via_pool_relay(pool_cfg)
                    relay_used = True
                except Exception as e:
                    if static_proxy:
                        emitter.warn(f"代理池 relay 检查失败，回退固定代理: {e}", step="check_proxy")
                    else:
                        emitter.warn(f"代理池 relay 检查失败，尝试直连代理: {e}", step="check_proxy")
            if not trace_text:
                trace_resp = session_get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
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
            try:
                email, dev_token = mail_provider.create_mailbox(
                    proxy=static_proxy, proxy_selector=mail_proxy_selector,
                )
            except TypeError:
                email, dev_token = mail_provider.create_mailbox(proxy=static_proxy)
        else:
            emitter.info("正在创建 Mail.tm 临时邮箱...", step="create_email")
            email, dev_token = get_email_and_token(
                static_proxies, emitter, proxy_selector=mail_proxies_selector,
            )
        if not email or not dev_token:
            emitter.error("临时邮箱创建失败", step="create_email")
            return None
        emitter.success(f"临时邮箱创建成功: {email}", step="create_email")

        # 生成随机密码
        _pw_chars = string.ascii_letters + string.digits + "!@#$%&*"
        account_password = "".join(secrets.choice(_pw_chars) for _ in range(16))

        if _stopped():
            return None

        # ------- 步骤3：通过 chatgpt.com 建立注册会话 -------
        emitter.info("正在访问 ChatGPT 首页...", step="oauth_init")
        _chatgpt_base = "https://chatgpt.com"

        session_get(f"{_chatgpt_base}/", timeout=20)

        csrf_resp = session_get(
            f"{_chatgpt_base}/api/auth/csrf",
            headers={**BROWSER_HEADERS, "referer": f"{_chatgpt_base}/"},
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

        did = s1.cookies.get("oai-did") or relay_cookie_jar.get("oai-did") or ""
        if not did:
            did = str(uuid.uuid4())
            relay_cookie_jar["oai-did"] = did
            try:
                s1.cookies.set("oai-did", did, domain="chatgpt.com")
            except Exception:
                try:
                    s1.cookies.set("oai-did", did)
                except Exception:
                    pass

        auth_session_id = str(uuid.uuid4())
        signin_params = urlencode({
            "prompt": "login", "ext-oai-did": did,
            "auth_session_logging_id": auth_session_id,
            "screen_hint": "login_or_signup", "login_hint": email,
        })
        signin_resp = session_post(
            f"{_chatgpt_base}/api/auth/signin/openai?{signin_params}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Referer": f"{_chatgpt_base}/",
                "Origin": _chatgpt_base,
            },
            data=urlencode({
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

        auth_resp = session_get(
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

        # ------- 步骤4+5：密码注册 -------
        time.sleep(random.uniform(0.5, 1.0))
        emitter.info("正在提交注册表单（密码模式）...", step="signup")
        _reg_headers = {
            "referer": "https://auth.openai.com/create-account/password",
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://auth.openai.com",
        }
        _reg_headers.update(_trace_headers())
        signup_resp = session_post(
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

        # ------- 步骤6：发送邮箱验证码 -------
        # 注意：这一步待用户调研确认是否还需要。
        # 如果 OpenAI 在 register 成功后自动发验证码，可以去掉。
        time.sleep(random.uniform(0.3, 0.8))
        emitter.info("正在发送邮箱验证码...", step="send_otp")
        otp_resp = session_get(
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
                    dev_token, email, proxy=static_proxy,
                    proxy_selector=mail_proxy_selector, stop_event=stop_event,
                )
            except TypeError:
                code = mail_provider.wait_for_otp(
                    dev_token, email, proxy=static_proxy, stop_event=stop_event,
                )
        else:
            code = get_oai_code(
                dev_token, email, static_proxies, emitter, stop_event,
                proxy_selector=mail_proxies_selector,
            )
        if not code:
            return None

        if _stopped():
            return None

        # ------- 步骤8：验证 OTP -------
        time.sleep(random.uniform(0.3, 0.8))
        emitter.info("正在验证 OTP...", step="verify_otp")
        _otp_headers = {
            "referer": "https://auth.openai.com/email-verification",
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://auth.openai.com",
        }
        _otp_headers.update(_trace_headers())
        code_resp = session_post(
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

        # ------- 步骤9：创建账户（带 Sentinel PoW）-------
        time.sleep(random.uniform(0.5, 1.5))
        emitter.info("正在创建账户信息...", step="create_account")

        # 初始化 Sentinel 生成器（在 create_account 之前，而非仅在 OAuth 阶段）
        sentinel = SentinelGen(did, ua1)

        def _build_sentinel(flow, session_get_fn, session_post_fn):
            """生成 Sentinel token（附带 PoW）"""
            req_body = json.dumps({"p": sentinel.gen_req_token(), "id": did, "flow": flow})
            sen_resp = session_post_fn(
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
                p_val = sentinel.gen_token(seed=pow_d["seed"], diff=pow_d.get("difficulty", "0"))
            else:
                p_val = sentinel.gen_req_token()
            return json.dumps({"p": p_val, "t": "", "c": c_val, "id": did, "flow": flow}, separators=(",", ":"))

        # 生成 create_account 的 sentinel token
        _sen_ca = _build_sentinel("create_account", session_get, session_post)
        if not _sen_ca:
            emitter.warn("Sentinel token (create_account) 获取失败，尝试不带 sentinel 继续...", step="create_account")

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
        # 新增：添加 Sentinel token 到 create_account 请求头
        if _sen_ca:
            _ca_headers["openai-sentinel-token"] = _sen_ca

        create_account_resp = session_post(
            "https://auth.openai.com/api/accounts/create_account",
            headers=_ca_headers,
            json={"name": _rand_name, "birthdate": _rand_bday},
        )
        create_account_status = create_account_resp.status_code
        emitter.info(f"账户创建状态: {create_account_status}", step="create_account")

        if create_account_status != 200:
            emitter.error(create_account_resp.text, step="create_account")
            return None

        emitter.success("账户创建成功！注册阶段完成。", step="create_account")

        # ============================
        # 丢弃注册 session
        # ============================
        try:
            s1.close()
        except Exception:
            pass
        emitter.info("注册 session 已关闭，准备新建登录 session...", step="get_token")

        if _stopped():
            return None

        # ============================
        # 第二阶段：全新会话走登录流程拿 Token
        # ============================
        time.sleep(random.uniform(1.0, 3.0))

        # 全新的 Chrome 指纹、session、device_id
        cp2, full2, ua2 = _make_chrome_fingerprint()
        s2 = _make_session(cp2, full2, ua2)
        login_get, login_post = _make_session_helpers(s2)
        did2 = str(uuid.uuid4())

        # 新 session 的 Sentinel 生成器
        sentinel2 = SentinelGen(did2, ua2)

        def _build_sentinel2(flow):
            """第二阶段的 Sentinel token 生成"""
            req_body = json.dumps({"p": sentinel2.gen_req_token(), "id": did2, "flow": flow})
            sen_resp = login_post(
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
                p_val = sentinel2.gen_token(seed=pow_d["seed"], diff=pow_d.get("difficulty", "0"))
            else:
                p_val = sentinel2.gen_req_token()
            return json.dumps({"p": p_val, "t": "", "c": c_val, "id": did2, "flow": flow}, separators=(",", ":"))

        def _oauth_headers(referer):
            h = dict(BROWSER_HEADERS)
            h.update({
                "content-type": "application/json",
                "origin": "https://auth.openai.com",
                "referer": referer,
                "oai-device-id": did2,
            })
            h.update(_trace_headers())
            return h

        try:
            # 10a: 生成 PKCE 参数
            oauth = generate_oauth_url()
            emitter.info("登录阶段 1/5: 初始化 OAuth...", step="get_token")

            # 设置 oai-did cookie
            try:
                s2.cookies.set("oai-did", did2, domain=".auth.openai.com")
                s2.cookies.set("oai-did", did2, domain="auth.openai.com")
            except Exception:
                pass

            # 10b: GET /oauth/authorize
            login_get(oauth.auth_url, timeout=30)

            if _stopped():
                return None

            # 10c: POST authorize/continue（提交邮箱）
            emitter.info("登录阶段 2/5: 提交邮箱...", step="get_token")
            _sen_ac = _build_sentinel2("authorize_continue")
            if not _sen_ac:
                emitter.error("Sentinel token (authorize_continue) 获取失败", step="get_token")
                return None
            _ac_headers = _oauth_headers("https://auth.openai.com/log-in")
            _ac_headers["openai-sentinel-token"] = _sen_ac
            _ac_resp = login_post(
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

            # 10d: POST password/verify（提交密码）
            emitter.info("登录阶段 3/5: 验证密码...", step="get_token")
            _sen_pw = _build_sentinel2("password_verify")
            if not _sen_pw:
                emitter.error("Sentinel token (password_verify) 获取失败", step="get_token")
                return None
            _pw_headers = _oauth_headers("https://auth.openai.com/log-in/password")
            _pw_headers["openai-sentinel-token"] = _sen_pw
            _pw_resp = login_post(
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

            # 登录阶段的 OTP 验证（不手动调 send，直接等自动发的验证码）
            _need_login_otp = (
                _page_type == "email_otp_verification"
                or "email-verification" in (_consent_url or "")
                or "email-otp" in (_consent_url or "")
            )
            if _need_login_otp:
                emitter.info("登录需要邮箱 OTP 验证（等待自动发送的验证码）...", step="get_token")
                if not dev_token or mail_provider is None:
                    # 没有 mail_provider 时回退到 Mail.tm
                    if not dev_token:
                        emitter.error("登录 OTP 验证需要邮箱 token，但不可用", step="get_token")
                        return None

                _otp_ok = False
                _otp_deadline = time.time() + 120
                _tried_codes: set = set()
                while time.time() < _otp_deadline and not _otp_ok:
                    if _stopped():
                        return None
                    if mail_provider is not None:
                        try:
                            _otp_code2 = mail_provider.wait_for_otp(
                                dev_token, email, proxy=static_proxy,
                                proxy_selector=mail_proxy_selector, stop_event=stop_event,
                            )
                        except TypeError:
                            _otp_code2 = mail_provider.wait_for_otp(
                                dev_token, email, proxy=static_proxy, stop_event=stop_event,
                            )
                    else:
                        _otp_code2 = get_oai_code(
                            dev_token, email, static_proxies, emitter, stop_event,
                            proxy_selector=mail_proxies_selector,
                        )
                    if not _otp_code2 or _otp_code2 in _tried_codes:
                        time.sleep(2)
                        continue
                    _tried_codes.add(_otp_code2)
                    emitter.info(f"登录 OTP 尝试: {_otp_code2}", step="get_token")
                    _otp2_h = _oauth_headers("https://auth.openai.com/email-verification")
                    _otp2_resp = login_post(
                        "https://auth.openai.com/api/accounts/email-otp/validate",
                        headers=_otp2_h,
                        json={"code": _otp_code2},
                    )
                    emitter.info(f"登录 OTP validate -> {_otp2_resp.status_code}", step="get_token")
                    if _otp2_resp.status_code == 200:
                        try:
                            _otp2_data = _otp2_resp.json()
                        except Exception:
                            _otp2_data = {}
                        _consent_url = str(_otp2_data.get("continue_url") or "").strip() or _consent_url
                        _page_type = str((_otp2_data.get("page") or {}).get("type", "")).strip() or _page_type
                        emitter.info(f"登录 OTP 验证通过 page={_page_type or '-'} next={(_consent_url or '-')[:140]}", step="get_token")
                        _otp_ok = True
                        break
                    time.sleep(2)

                if not _otp_ok:
                    emitter.error(f"登录 OTP 验证失败，已尝试 {len(_tried_codes)} 个验证码", step="get_token")
                    return None

            if _stopped():
                return None

            # 10e: 提取 authorization code（workspace/org 选择）
            _AUTH = "https://auth.openai.com"

            def _extract_code(url):
                if not url or "code=" not in url:
                    return None
                try:
                    return parse_qs(urlparse(url).query).get("code", [None])[0]
                except Exception:
                    return None

            def _follow_for_code(start_url):
                url = start_url
                for _ in range(12):
                    try:
                        r = login_get(url, allow_redirects=False, timeout=15)
                    except Exception as e:
                        m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
                        if m:
                            return _extract_code(m.group(1))
                        return None
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("Location", "")
                        if not loc:
                            break
                        next_url = urljoin(url, loc)
                        c = _extract_code(next_url)
                        if c:
                            return c
                        url = next_url
                        continue
                    break
                return None

            def _ws_org_select(consent_ref):
                _auth_ck = s2.cookies.get("oai-client-auth-session") or relay_cookie_jar.get("oai-client-auth-session") or ""
                _ck_data = None
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
                _ws_resp = login_post(
                    f"{_AUTH}/api/accounts/workspace/select",
                    headers=_ws_h,
                    json={"workspace_id": _ws_id},
                    allow_redirects=False,
                )
                emitter.info(f"workspace/select -> {_ws_resp.status_code}", step="workspace")

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
                        _org_resp = login_post(
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

                if _ws_next:
                    if _ws_next.startswith("/"):
                        _ws_next = f"{_AUTH}{_ws_next}"
                    c = _extract_code(_ws_next)
                    if c:
                        return c
                    return _follow_for_code(_ws_next)

                return None

            # 提取 authorization code
            _code = None

            if _consent_url and _consent_url.startswith("/"):
                _consent_url = f"{_AUTH}{_consent_url}"
            if not _consent_url and "consent" in _page_type:
                _consent_url = f"{_AUTH}/sign-in-with-chatgpt/codex/consent"

            if _consent_url:
                _code = _extract_code(_consent_url)

            if not _code and _consent_url:
                emitter.info("登录阶段 4/5: 跟随 consent URL...", step="get_token")
                _code = _follow_for_code(_consent_url)

            _consent_hint = any(kw in (_consent_url or "") for kw in ["consent", "workspace", "organization", "sign-in-with"])
            _consent_hint = _consent_hint or any(kw in _page_type for kw in ["consent", "organization"])
            if not _code and (_consent_hint or not _consent_url):
                emitter.info("登录阶段 4/5: 处理 workspace/org...", step="workspace")
                _ws_ref = _consent_url or f"{_AUTH}/sign-in-with-chatgpt/codex/consent"
                _code = _ws_org_select(_ws_ref)

            if not _code:
                emitter.info("登录阶段 4/5: 回退 consent 路径...", step="get_token")
                _code = _ws_org_select(f"{_AUTH}/sign-in-with-chatgpt/codex/consent")
                if not _code:
                    _code = _follow_for_code(f"{_AUTH}/sign-in-with-chatgpt/codex/consent")

            if not _code:
                emitter.error("未能获取 OAuth authorization code", step="get_token")
                try:
                    s2.close()
                except Exception:
                    pass
                return None

            # 10f: POST /oauth/token
            emitter.info("登录阶段 5/5: 交换 Token...", step="get_token")
            _token_resp = login_post(
                TOKEN_URL,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                data=urlencode({
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
                try:
                    s2.close()
                except Exception:
                    pass
                return None

            try:
                _token_json = _token_resp.json()
            except Exception:
                _token_json = json.loads(str(_token_resp.text or "{}"))

            emitter.success("Token 获取成功！", step="get_token")
            try:
                s2.close()
            except Exception:
                pass
            return _build_token_result(_token_json, account_password=account_password)

        except Exception as e:
            emitter.error(f"登录阶段发生错误: {e}", step="get_token")
            try:
                s2.close()
            except Exception:
                pass
            return None

    except Exception as e:
        emitter.error(f"注册阶段发生错误: {e}", step="runtime")
        try:
            s1.close()
        except Exception:
            pass
        return None


def main():
    """CLI 入口"""
    import argparse
    parser = argparse.ArgumentParser(description="OpenAI 账号注册工具 (V2 双会话版)")
    parser.add_argument("--proxy", type=str, default="", help="代理地址")
    parser.add_argument("--once", action="store_true", help="单次注册后退出")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最小间隔(秒)")
    parser.add_argument("--sleep-max", type=int, default=30, help="循环模式最大间隔(秒)")
    args = parser.parse_args()

    # 加载配置
    config_path = os.path.join(os.path.dirname(__file__), "..", "data", "sync_config.json")
    if not os.path.exists(config_path):
        print(f"配置文件不存在: {config_path}")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    # 构建邮箱提供商
    from .mail_providers import MultiMailRouter, create_provider_by_name
    providers = []
    for pname in config.get("mail_providers", ["cloudflare_temp_email"]):
        pcfg = config.get("mail_provider_configs", {}).get(pname, {})
        try:
            p = create_provider_by_name(pname, pcfg)
            providers.append(p)
        except Exception as e:
            print(f"邮箱提供商 {pname} 初始化失败: {e}")

    if not providers:
        print("没有可用的邮箱提供商")
        sys.exit(1)

    router = MultiMailRouter(providers, strategy=config.get("mail_strategy", "round_robin"))

    # 代理池配置
    proxy_pool_cfg = None
    if config.get("proxy_pool_enabled"):
        proxy_pool_cfg = {
            "api_url": config.get("proxy_pool_api_url"),
            "auth_mode": config.get("proxy_pool_auth_mode"),
            "api_key": config.get("proxy_pool_api_key"),
            "count": config.get("proxy_pool_count", 1),
            "country": config.get("proxy_pool_country", "US"),
        }

    proxy_val = args.proxy or config.get("proxy", "")

    if args.once:
        result = run_v2(proxy_val, mail_provider=router, proxy_pool_config=proxy_pool_cfg)
        sys.exit(0 if result else 1)
    else:
        import random
        while True:
            run_v2(proxy_val, mail_provider=router, proxy_pool_config=proxy_pool_cfg)
            sleep_sec = random.randint(args.sleep_min, args.sleep_max)
            print(f"\n等待 {sleep_sec} 秒后继续...\n")
            time.sleep(sleep_sec)


if __name__ == "__main__":
    main()


# ==========================================
# CLI 入口
# ==========================================

def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI 账号池编排器 - 新版双会话注册脚本")
    parser.add_argument("--proxy", default=None, help="代理地址，如 http://127.0.0.1:7897")
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument("--sleep-max", type=int, default=30, help="循环模式最长等待秒数")
    args = parser.parse_args()

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
