"""
register_v3.py - 纯协议注册流程（移植自 codexgen/protocol_keygen.py）

核心特点：
1. 完整 Sentinel PoW（FNV-1a + 环境数组伪造 + 暴力搜索）
2. 完整请求头（sec-ch-ua、sec-fetch-*、Datadog trace、oai-device-id）
3. 双候选 OTP 验证
4. 完整登录换 token（consent 多步流程）
5. 与 server.py 接口兼容（run_v3 签名不变）
"""

import json
import os
import re
import time
import uuid
import random
import string
import secrets
import hashlib
import base64
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 从 register.py 复用
from .register import (
    EventEmitter,
    _cli_emitter,
    _augment_token_payload,
    _build_token_result,
    _normalize_proxy_value,
    CLIENT_ID,
    DEFAULT_REDIRECT_URI,
    TOKENS_DIR,
)

# =================== 常量 ===================

AUTH_BASE = "https://auth.openai.com"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

# API 请求头模板（从 cURL 逆向提取）
COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": AUTH_BASE,
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

# 页面导航请求头（用于 GET 类请求）
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}


# =================== 工具函数 ===================


def _generate_device_id() -> str:
    return str(uuid.uuid4())


def _generate_random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    pwd = list(
        random.choice(string.ascii_uppercase)
        + random.choice(string.ascii_lowercase)
        + random.choice(string.digits)
        + random.choice("!@#$%")
        + "".join(random.choice(chars) for _ in range(length - 4))
    )
    random.shuffle(pwd)
    return "".join(pwd)


def _generate_random_name():
    first = [
        "James", "Robert", "John", "Michael", "David", "William", "Richard",
        "Mary", "Jennifer", "Linda", "Elizabeth", "Susan", "Jessica", "Sarah",
        "Emily", "Emma", "Olivia", "Sophia", "Liam", "Noah", "Oliver", "Ethan",
    ]
    last = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
        "Davis", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Martin",
    ]
    return random.choice(first), random.choice(last)


def _generate_random_birthday() -> str:
    year = random.randint(1996, 2006)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def _generate_datadog_trace() -> dict:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), '016x')
    parent_hex = format(int(parent_id), '016x')
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def _generate_pkce():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _response_preview(resp, limit: int = 300) -> str:
    if not resp:
        return "无响应"
    text = ""
    try:
        text = str(resp.text or "").strip()
    except Exception:
        text = ""
    if not text:
        try:
            text = json.dumps(resp.json(), ensure_ascii=False)
        except Exception:
            text = ""
    if not text:
        return f"HTTP {getattr(resp, 'status_code', '未知')}"
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _extract_openai_error_code(resp) -> Optional[str]:
    if not resp:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if not isinstance(err, dict):
        return None
    code = str(err.get("code") or "").strip()
    return code or None


# =================== HTTP 会话管理 ===================


def _create_session(proxy: str = "") -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


# =================== Sentinel Token PoW 生成 ===================


class SentinelTokenGenerator:
    """
    Sentinel Token 纯 Python 生成器

    通过逆向 sentinel SDK 的 PoW 算法，
    纯 Python 构造合法的 openai-sentinel-token。
    """

    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id or _generate_device_id()
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        """FNV-1a 32位哈希算法 + xorshift 混合（从 SDK JS 逆向还原）"""
        h = 2166136261  # FNV offset basis
        for ch in text:
            code = ord(ch)
            h ^= code
            h = ((h * 16777619) & 0xFFFFFFFF)

        # xorshift 混合（murmurhash3 finalizer）
        h ^= (h >> 16)
        h = ((h * 2246822507) & 0xFFFFFFFF)
        h ^= (h >> 13)
        h = ((h * 3266489909) & 0xFFFFFFFF)
        h ^= (h >> 16)
        h = h & 0xFFFFFFFF

        return format(h, '08x')

    def _get_config(self) -> list:
        """构造浏览器环境数据数组（_getConfig 方法逆向还原）"""
        screen_info = "1920x1080"
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        js_heap_limit = 4294705152
        nav_random1 = random.random()
        ua = USER_AGENT
        script_src = "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js"
        script_version = None
        data_build = None
        language = "en-US"
        languages = "en-US,en"
        nav_random2 = random.random()
        nav_props = [
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ]
        nav_prop = random.choice(nav_props)
        nav_val = f"{nav_prop}\u2212undefined"  # SDK 用 − (U+2212) 而非 - (U+002D)
        doc_key = random.choice(["location", "implementation", "URL", "documentURI", "compatMode"])
        win_key = random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"])
        perf_now = random.uniform(1000, 50000)
        hardware_concurrency = random.choice([4, 8, 12, 16])
        time_origin = time.time() * 1000 - perf_now

        return [
            screen_info,           # [0]
            date_str,              # [1]
            js_heap_limit,         # [2]
            nav_random1,           # [3] 占位，后被 nonce 替换
            ua,                    # [4]
            script_src,            # [5]
            script_version,        # [6]
            data_build,            # [7]
            language,              # [8]
            languages,             # [9] 占位，后被耗时替换
            nav_random2,           # [10]
            nav_val,               # [11]
            doc_key,               # [12]
            win_key,               # [13]
            perf_now,              # [14]
            self.sid,              # [15]
            "",                    # [16]
            hardware_concurrency,  # [17]
            time_origin,           # [18]
        ]

    @staticmethod
    def _base64_encode(data) -> str:
        json_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        encoded = json_str.encode('utf-8')
        return base64.b64encode(encoded).decode('ascii')

    def _run_check(self, start_time: float, seed: str, difficulty: str, config: list, nonce: int) -> Optional[str]:
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)

        data = self._base64_encode(config)
        hash_input = seed + data
        hash_hex = self._fnv1a_32(hash_input)

        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"

        return None

    def generate_token(self, seed: Optional[str] = None, difficulty: Optional[str] = None) -> str:
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"

        if difficulty is None:
            difficulty = "0"

        start_time = time.time()
        config = self._get_config()

        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result

        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self) -> str:
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        data = self._base64_encode(config)
        return "gAAAAAC" + data  # 注意前缀是 C 不是 B


# =================== Sentinel API ===================

_SENTINEL_HEADER_CACHE: Dict[tuple, str] = {}
_SENTINEL_SO_TOKEN_CACHE: Dict[tuple, str] = {}


def _fetch_sentinel_challenge(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[dict]:
    """调用 sentinel 后端 API 获取 challenge 数据（c 字段 + PoW 参数）"""
    gen = SentinelTokenGenerator(device_id=device_id)
    p_token = gen.generate_requirements_token()

    req_body = {"p": p_token, "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "User-Agent": USER_AGENT,
        "Origin": "https://sentinel.openai.com",
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

    try:
        resp = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            data=json.dumps(req_body),
            headers=headers,
            timeout=15,
            verify=False,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        # DEBUG: 打印 sentinel/req 响应的所有顶层字段
        keys_info = {k: (type(v).__name__, len(str(v)) if isinstance(v, (str, list, dict)) else v) for k, v in data.items()}
        print(f"[DEBUG sentinel/req] flow={flow} response keys: {keys_info}")
        # DEBUG: turnstile 内部结构
        if "turnstile" in data and isinstance(data["turnstile"], dict):
            ts = data["turnstile"]
            ts_info = {k: (type(v).__name__, len(str(v)) if isinstance(v, (str, list, dict)) else v) for k, v in ts.items()}
            print(f"[DEBUG sentinel/req] flow={flow} turnstile keys: {ts_info}")
        # DEBUG: so 内部结构
        if "so" in data and isinstance(data["so"], dict):
            so = data["so"]
            so_info = {k: (type(v).__name__, len(str(v)) if isinstance(v, (str, list, dict)) else v) for k, v in so.items()}
            print(f"[DEBUG sentinel/req] flow={flow} so keys: {so_info}")
        return data
    except Exception:
        return None


def _build_sentinel_token(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[str]:
    """构建完整的 openai-sentinel-token JSON 字符串"""
    cache_key = (flow, device_id)
    challenge = _fetch_sentinel_challenge(session, device_id, flow)
    if not challenge:
        return _SENTINEL_HEADER_CACHE.get(cache_key)

    c_value = challenge.get("token", "")
    pow_data = challenge.get("proofofwork", {})
    gen = SentinelTokenGenerator(device_id=device_id)

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.generate_token(
            seed=pow_data["seed"],
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = gen.generate_requirements_token()

    sentinel_token = json.dumps({
        "p": p_value,
        "t": "",
        "c": c_value,
        "id": device_id,
        "flow": flow,
    }, separators=(",", ":"))
    _SENTINEL_HEADER_CACHE[cache_key] = sentinel_token
    return sentinel_token


def _fetch_sentinel_so_token(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[str]:
    """获取 openai-sentinel-so-token 所需的原始 token（c 字段）"""
    cache_key = (flow, device_id)
    challenge = _fetch_sentinel_challenge(session, device_id, flow)
    if not challenge:
        return _SENTINEL_SO_TOKEN_CACHE.get(cache_key)
    token = str(challenge.get("token") or "").strip()
    if token:
        _SENTINEL_SO_TOKEN_CACHE[cache_key] = token
    return token or None


# =================== 请求头构造 ===================


def _build_api_headers(device_id: str, referer: str, with_sentinel: bool = False,
                       sentinel_token_str: Optional[str] = None) -> dict:
    """构造 API 请求头（COMMON_HEADERS + datadog + oai-device-id）"""
    headers = dict(COMMON_HEADERS)
    headers["referer"] = referer
    headers["oai-device-id"] = device_id
    headers.update(_generate_datadog_trace())
    if with_sentinel and sentinel_token_str:
        headers["openai-sentinel-token"] = sentinel_token_str
    return headers


# =================== 创建账号 (about-you) ===================


def _complete_about_you(session: requests.Session, device_id: str, name: str, birthday: str,
                        emitter: EventEmitter) -> Optional[str]:
    """完成 about-you 资料提交（双候选策略），成功返回 continue_url，失败返回 None"""

    # 先 GET /about-you 页面，建立正确的 session/cookie 状态
    try:
        h_nav = dict(NAVIGATE_HEADERS)
        h_nav["referer"] = f"{AUTH_BASE}/email-verification"
        session.get(f"{AUTH_BASE}/about-you", headers=h_nav,
                    verify=False, timeout=30, allow_redirects=True)
    except Exception as e:
        emitter.warn(f"GET /about-you 失败（继续尝试）: {e}", step="create_account")

    create_so_token = _fetch_sentinel_so_token(session, device_id, flow="oauth_create_account")
    create_sentinel = _build_sentinel_token(session, device_id, flow="oauth_create_account")

    base_headers = dict(COMMON_HEADERS)
    base_headers["referer"] = f"{AUTH_BASE}/about-you"
    base_headers["oai-device-id"] = device_id
    base_headers.update(_generate_datadog_trace())

    payload = {"name": name, "birthdate": birthday}
    candidates = []

    # 候选1: 仅 so-token
    legacy_headers = dict(base_headers)
    if create_so_token:
        legacy_headers["openai-sentinel-so-token"] = create_so_token
    candidates.append(("so-token", f"{AUTH_BASE}/api/accounts/create_account", legacy_headers, payload))

    # 候选2: so-token + sentinel-token
    legacy_headers_with_sentinel = dict(legacy_headers)
    if create_sentinel:
        legacy_headers_with_sentinel["openai-sentinel-token"] = create_sentinel
    candidates.append(("so-token+sentinel-token", f"{AUTH_BASE}/api/accounts/create_account",
                        legacy_headers_with_sentinel, payload))

    errors = []
    for label, url, headers, data in candidates:
        try:
            resp = session.post(url, headers=headers, data=json.dumps(data, separators=(",", ":")),
                                verify=False, timeout=30)
        except Exception as exc:
            errors.append(f"{label}: {exc}")
            continue

        if 200 <= resp.status_code < 300:
            try:
                resp_data = resp.json()
                return resp_data.get("continue_url", "")
            except Exception:
                return ""

        # registration_disallowed 时重新获取 sentinel 重试
        if resp.status_code == 400 and "registration_disallowed" in (resp.text or ""):
            emitter.info(f"{label}: registration_disallowed，重新获取 sentinel 重试...", step="create_account")
            fresh_sentinel = _build_sentinel_token(session, device_id, flow="oauth_create_account")
            if fresh_sentinel:
                headers["openai-sentinel-token"] = fresh_sentinel
                try:
                    resp2 = session.post(url, headers=headers, data=json.dumps(data, separators=(",", ":")),
                                         verify=False, timeout=30)
                    if 200 <= resp2.status_code < 300:
                        try:
                            resp_data = resp2.json()
                            return resp_data.get("continue_url", "")
                        except Exception:
                            return ""
                except Exception:
                    pass

        err_code = _extract_openai_error_code(resp)
        error_line = f"{label}: HTTP {resp.status_code} {_response_preview(resp)}"
        if err_code:
            error_line += f" [code={err_code}]"
        errors.append(error_line)

    if errors:
        emitter.error(f"账户信息填写失败: {errors[0]}", step="create_account")
    return None


# =================== consent 流程辅助函数 ===================


def _extract_code_from_url(url: str) -> Optional[str]:
    if not url or "code=" not in url:
        return None
    try:
        return parse_qs(urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None


def _decode_auth_session(session_obj: requests.Session) -> Optional[dict]:
    """从 oai-client-auth-session cookie 解码 JSON"""
    for c in session_obj.cookies:
        if c.name == "oai-client-auth-session":
            val = c.value
            first_part = val.split(".")[0] if "." in val else val
            pad = 4 - len(first_part) % 4
            if pad != 4:
                first_part += "=" * pad
            try:
                raw = base64.urlsafe_b64decode(first_part)
                return json.loads(raw.decode("utf-8"))
            except Exception:
                pass
    return None


def _follow_and_extract_code(session_obj: requests.Session, url: str, max_depth: int = 10) -> Optional[str]:
    """跟随 URL，从 302 Location 或 ConnectionError 中提取 code"""
    if max_depth <= 0:
        return None
    try:
        r = session_obj.get(url, headers=NAVIGATE_HEADERS, verify=False,
                            timeout=15, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            code = _extract_code_from_url(loc)
            if code:
                return code
            if loc.startswith("/"):
                loc = f"{AUTH_BASE}{loc}"
            return _follow_and_extract_code(session_obj, loc, max_depth - 1)
        elif r.status_code == 200:
            return _extract_code_from_url(r.url)
    except requests.exceptions.ConnectionError as e:
        url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
        if url_match:
            return _extract_code_from_url(url_match.group(1))
    except Exception:
        pass
    return None


# =================== Session Fast Path（从 create_account 的 continue_url 直接拿 token） ===================


def _jwt_claims_no_verify(token: str) -> dict:
    """解析 JWT payload，不验签"""
    if not token:
        return {}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def _build_compat_id_token(email: str, account_id: str, user_id: str = "",
                            plan_type: str = "free", exp: int = 0) -> str:
    """构造最小兼容 id_token JWT（无签名，仅供 CPA 解析字段用）"""
    header = {"alg": "none", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "email": email,
        "iat": now,
        "exp": exp or (now + 3600),
        "sub": user_id or "",
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": user_id or account_id,
            "plan_type": plan_type,
        },
    }
    h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{h}.{p}."


def _session_fast_path(session: requests.Session, continue_url: str,
                        email: str, password: str, proxy_str: str,
                        emitter: EventEmitter) -> Optional[str]:
    """
    Session fast path: 用 create_account 返回的 continue_url 直接获取 token，
    避免二次登录触发额外 OTP。

    返回: token_json 字符串，失败返回 None
    """
    if not continue_url:
        return None

    # continue_url 可能是相对路径
    if continue_url.startswith("/"):
        callback_url = f"https://chatgpt.com{continue_url}"
    else:
        callback_url = continue_url

    # 必须是 chatgpt.com 的 callback URL 且带 code 参数
    if "chatgpt.com" not in callback_url or "code=" not in callback_url:
        emitter.info(f"continue_url 不是 chatgpt callback: {callback_url[:120]}", step="get_token")
        return None

    emitter.info("使用 session fast path 获取 Token...", step="get_token")

    # 新建 session 访问 chatgpt.com callback
    chatgpt_session = _create_session(proxy_str)

    # 步骤1: GET callback URL，让 ChatGPT 完成 code exchange 建立 session
    try:
        resp = chatgpt_session.get(
            callback_url,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "user-agent": USER_AGENT,
                "upgrade-insecure-requests": "1",
            },
            allow_redirects=True,
            verify=False,
            timeout=30,
        )
        emitter.info(f"callback -> HTTP {resp.status_code} final={resp.url[:100]}", step="get_token")
    except Exception as e:
        emitter.warn(f"callback 请求失败: {e}", step="get_token")
        return None

    # 步骤2: GET /api/auth/session 拿 accessToken
    try:
        resp = chatgpt_session.get(
            "https://chatgpt.com/api/auth/session",
            headers={
                "accept": "application/json",
                "user-agent": USER_AGENT,
                "referer": "https://chatgpt.com/",
            },
            verify=False,
            timeout=30,
        )
    except Exception as e:
        emitter.warn(f"session 请求失败: {e}", step="get_token")
        return None

    if resp.status_code != 200:
        emitter.warn(f"session 响应: HTTP {resp.status_code}", step="get_token")
        return None

    try:
        session_data = resp.json()
    except Exception:
        emitter.warn("session 响应解析失败", step="get_token")
        return None

    access_token = session_data.get("accessToken") or session_data.get("access_token") or ""
    if not access_token:
        emitter.warn("session 中未找到 accessToken", step="get_token")
        return None

    # 解析 JWT
    claims = _jwt_claims_no_verify(access_token)
    token_email = claims.get("email") or email
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = auth_claims.get("chatgpt_account_id") or ""
    user_id = auth_claims.get("chatgpt_user_id") or ""
    plan_type = auth_claims.get("plan_type") or "free"
    exp = claims.get("exp") or 0

    if not account_id:
        emitter.warn("accessToken 中无 chatgpt_account_id", step="get_token")
        return None

    # 构造兼容 id_token
    compat_id_token = _build_compat_id_token(
        email=token_email, account_id=account_id,
        user_id=user_id, plan_type=plan_type, exp=exp,
    )

    refresh_token = session_data.get("refreshToken") or session_data.get("refresh_token") or ""
    session_token = session_data.get("sessionToken") or session_data.get("session_token") or ""

    now = int(time.time())
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    exp_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)) if exp else now_rfc3339

    token_obj = {
        "type": "codex",
        "email": token_email,
        "id_token": compat_id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_token": session_token,
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": user_id,
        "last_refresh": now_rfc3339,
        "expires_at": exp_rfc3339,
        "expired": exp_rfc3339,
        "credentials": {
            "id_token": compat_id_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_token": session_token,
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": user_id,
        },
    }
    if password:
        token_obj["account_password"] = password

    at_len = len(access_token)
    has_rt = bool(refresh_token)
    emitter.success(f"session fast path 成功 (AT长度: {at_len}, RT: {has_rt}, account: {account_id[:8]}...)", step="get_token")

    return json.dumps(token_obj, ensure_ascii=False, separators=(",", ":"))


# =================== 登录换 Token（备用，当 fast path 不可用时） ===================


def _perform_login(session: requests.Session, email: str, password: str,
                   device_id: str, code_verifier: str,
                   emitter: EventEmitter, mail_provider, otp_token: str,
                   proxy_str: str,
                   stop_event: Optional[threading.Event] = None,
                   used_otp_codes: Optional[set] = None) -> Optional[dict]:
    """
    纯 HTTP OAuth 登录换 Token（移植自 codexgen perform_codex_oauth_login_http）

    返回 token dict 或 None
    """
    # 新建独立 session
    login_session = _create_session(proxy_str)
    login_device_id = _generate_device_id()

    # 设置 oai-did cookie
    login_session.cookies.set("oai-did", login_device_id, domain=".auth.openai.com")
    login_session.cookies.set("oai-did", login_device_id, domain="auth.openai.com")

    # PKCE
    login_verifier, login_challenge = _generate_pkce()
    login_state = secrets.token_urlsafe(32)

    authorize_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "scope": "openid profile email offline_access",
        "code_challenge": login_challenge,
        "code_challenge_method": "S256",
        "state": login_state,
    }
    authorize_url = f"{AUTH_BASE}/oauth/authorize?{urlencode(authorize_params)}"

    # ===== 步骤1: GET /oauth/authorize =====
    emitter.info("[登录] GET /oauth/authorize ...", step="login")
    try:
        resp = login_session.get(
            authorize_url,
            headers=NAVIGATE_HEADERS,
            allow_redirects=True,
            verify=False,
            timeout=30,
        )
    except Exception as e:
        emitter.error(f"[登录] OAuth 授权请求失败: {e}", step="login")
        return None

    has_login_session = any(c.name == "login_session" for c in login_session.cookies)
    if not has_login_session:
        emitter.warn("[登录] 未获得 login_session cookie", step="login")

    # ===== 步骤2: POST authorize/continue =====
    emitter.info("[登录] POST authorize/continue ...", step="login")
    headers = dict(COMMON_HEADERS)
    headers["referer"] = f"{AUTH_BASE}/log-in"
    headers["oai-device-id"] = login_device_id
    headers.update(_generate_datadog_trace())

    sentinel_email = _build_sentinel_token(login_session, login_device_id, flow="authorize_continue")
    if not sentinel_email:
        emitter.error("[登录] 无法获取 authorize_continue sentinel token", step="login")
        return None
    headers["openai-sentinel-token"] = sentinel_email

    try:
        resp = login_session.post(
            f"{AUTH_BASE}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=headers,
            verify=False,
            timeout=30,
        )
    except Exception as e:
        emitter.error(f"[登录] 邮箱提交失败: {e}", step="login")
        return None

    if resp.status_code != 200:
        emitter.error(f"[登录] 邮箱提交失败: HTTP {resp.status_code} {_response_preview(resp)}", step="login")
        return None

    page_type = ""
    try:
        data = resp.json()
        page_type = data.get("page", {}).get("type", "")
    except Exception:
        pass

    # ===== 步骤3: POST password/verify =====
    emitter.info("[登录] POST password/verify ...", step="login")
    headers["referer"] = f"{AUTH_BASE}/log-in/password"
    headers.update(_generate_datadog_trace())

    sentinel_pwd = _build_sentinel_token(login_session, login_device_id, flow="password_verify")
    if not sentinel_pwd:
        emitter.error("[登录] 无法获取 password_verify sentinel token", step="login")
        return None
    headers["openai-sentinel-token"] = sentinel_pwd

    try:
        resp = login_session.post(
            f"{AUTH_BASE}/api/accounts/password/verify",
            json={"password": password},
            headers=headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
    except Exception as e:
        emitter.error(f"[登录] 密码提交失败: {e}", step="login")
        return None

    if resp.status_code != 200:
        emitter.error(f"[登录] 密码验证失败: HTTP {resp.status_code} {_response_preview(resp)}", step="login")
        return None

    continue_url = ""
    try:
        data = resp.json()
        continue_url = data.get("continue_url", "")
        page_type = data.get("page", {}).get("type", "")
    except Exception:
        page_type = ""

    if not continue_url:
        emitter.error("[登录] 未获取到 continue_url", step="login")
        return None

    emitter.info(f"[登录] password/verify -> page.type={page_type}", step="login")

    # ===== 步骤3.5: 邮箱验证（新注册账号首次登录时可能触发） =====
    if page_type == "email_otp_verification" or "email-verification" in continue_url:
        emitter.info("[登录] 检测到 email_otp_verification，等待验证码...", step="login_otp")

        if not mail_provider or not otp_token:
            emitter.error("[登录] 无 mail_provider/otp_token，无法接收验证码", step="login_otp")
            return None

        tried_codes = set(used_otp_codes or [])
        otp_ok = False

        h_val = dict(COMMON_HEADERS)
        h_val["referer"] = f"{AUTH_BASE}/email-verification"
        h_val["oai-device-id"] = login_device_id
        h_val.update(_generate_datadog_trace())

        # 分段等待 + resend 重试（与注册步骤5一致：初始120s, resend后45/90/120s）
        login_wait_rounds = [120, 45, 90, 120]

        for attempt, wait_sec in enumerate(login_wait_rounds):
            if stop_event and stop_event.is_set():
                return None

            # 后续轮次先 resend
            if attempt > 0:
                emitter.info(f"[登录] 未收到验证码，第 {attempt} 次 resend...", step="login_otp")
                h_resend = dict(COMMON_HEADERS)
                h_resend["referer"] = f"{AUTH_BASE}/email-verification"
                h_resend["oai-device-id"] = login_device_id
                h_resend.update(_generate_datadog_trace())
                sentinel_resend = _build_sentinel_token(login_session, login_device_id, flow="authorize_continue")
                if sentinel_resend:
                    h_resend["openai-sentinel-token"] = sentinel_resend
                try:
                    resp_resend = login_session.post(
                        f"{AUTH_BASE}/api/accounts/email-otp/resend",
                        headers=h_resend, json={},
                        verify=False, timeout=30,
                    )
                    emitter.info(f"[登录] resend 响应: HTTP {resp_resend.status_code}", step="login_otp")
                except Exception as e:
                    emitter.warn(f"[登录] resend 请求失败: {e}", step="login_otp")

            # 在本轮 wait_sec 内轮询验证码
            round_deadline = time.time() + wait_sec
            while time.time() < round_deadline and not otp_ok:
                if stop_event and stop_event.is_set():
                    return None

                try:
                    otp_code = mail_provider.wait_for_otp(
                        otp_token, email, proxy=proxy_str, stop_event=stop_event,
                        timeout=min(10, max(1, int(round_deadline - time.time()))),
                    )
                except TypeError:
                    otp_code = mail_provider.wait_for_otp(
                        otp_token, email, proxy=proxy_str,
                        timeout=min(10, max(1, int(round_deadline - time.time()))),
                    )

                if not otp_code or otp_code in tried_codes:
                    time.sleep(2)
                    continue

                tried_codes.add(otp_code)
                emitter.info(f"[登录] 尝试验证码: {otp_code}", step="login_otp")

                try:
                    resp = login_session.post(
                        f"{AUTH_BASE}/api/accounts/email-otp/validate",
                        json={"code": otp_code},
                        headers=h_val, verify=False, timeout=30,
                    )
                except Exception as e:
                    emitter.warn(f"[登录] validate 请求失败: {e}", step="login_otp")
                    continue

                if resp.status_code == 200:
                    otp_ok = True
                    emitter.success(f"[登录] OTP 验证成功: {otp_code}", step="login_otp")
                    try:
                        data = resp.json()
                        continue_url = data.get("continue_url", "")
                        page_type = data.get("page", {}).get("type", "")
                    except Exception:
                        pass
                    break
                else:
                    emitter.info(f"[登录] 验证码 {otp_code} 失败: {resp.status_code} {_response_preview(resp)}", step="login_otp")
                    time.sleep(2)

            if otp_ok:
                break

        if not otp_ok:
            emitter.error("[登录] OTP 验证超时（已重试 resend）", step="login_otp")
            return None

        # 如果进入 about-you
        if "about-you" in continue_url:
            emitter.info("[登录] 处理 about-you ...", step="login")
            h_about = dict(NAVIGATE_HEADERS)
            h_about["referer"] = f"{AUTH_BASE}/email-verification"
            resp_about = login_session.get(
                f"{AUTH_BASE}/about-you",
                headers=h_about, verify=False, timeout=30, allow_redirects=True,
            )
            if "consent" in resp_about.url or "organization" in resp_about.url:
                continue_url = resp_about.url
            else:
                first, last = _generate_random_name()
                name = f"{first} {last}"
                birthdate = _generate_random_birthday()
                h_create = dict(COMMON_HEADERS)
                h_create["referer"] = f"{AUTH_BASE}/about-you"
                h_create["oai-device-id"] = login_device_id
                h_create.update(_generate_datadog_trace())
                resp_create = login_session.post(
                    f"{AUTH_BASE}/api/accounts/create_account",
                    json={"name": name, "birthdate": birthdate},
                    headers=h_create, verify=False, timeout=30,
                )
                if resp_create.status_code == 200:
                    try:
                        data = resp_create.json()
                        continue_url = data.get("continue_url", "")
                    except Exception:
                        pass
                elif resp_create.status_code == 400 and "already_exists" in resp_create.text:
                    continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

        if "consent" in page_type:
            continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"

        if not continue_url or "email-verification" in continue_url:
            emitter.error("[登录] 邮箱验证后未获取到 consent URL", step="login")
            return None

    # ===== 步骤4: consent 多步流程 → 提取 code =====
    emitter.info("[登录] consent 多步流程...", step="consent")

    if continue_url.startswith("/"):
        consent_url = f"{AUTH_BASE}{continue_url}"
    else:
        consent_url = continue_url

    auth_code = None

    # 4a: GET consent 页面
    emitter.info("[登录] [4a] GET consent ...", step="consent")
    try:
        resp = login_session.get(consent_url, headers=NAVIGATE_HEADERS,
                                 verify=False, timeout=30, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            auth_code = _extract_code_from_url(loc)
            if not auth_code:
                auth_code = _follow_and_extract_code(login_session, loc)
        elif resp.status_code == 200:
            pass  # 继续后续步骤
    except requests.exceptions.ConnectionError as e:
        url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
        if url_match:
            auth_code = _extract_code_from_url(url_match.group(1))
    except Exception as e:
        emitter.warn(f"[登录] consent 请求异常: {e}", step="consent")

    # 4b: workspace/select
    if not auth_code:
        emitter.info("[登录] [4b] 解码 session -> workspace/select ...", step="consent")
        session_data = _decode_auth_session(login_session)

        workspace_id = None
        if session_data:
            workspaces = session_data.get("workspaces", [])
            if workspaces:
                workspace_id = workspaces[0].get("id")

        if workspace_id:
            h_consent = dict(COMMON_HEADERS)
            h_consent["referer"] = consent_url
            h_consent["oai-device-id"] = login_device_id
            h_consent.update(_generate_datadog_trace())

            try:
                resp = login_session.post(
                    f"{AUTH_BASE}/api/accounts/workspace/select",
                    json={"workspace_id": workspace_id},
                    headers=h_consent, verify=False, timeout=30, allow_redirects=False,
                )

                if resp.status_code in (301, 302, 303, 307, 308):
                    auth_code = _extract_code_from_url(resp.headers.get("Location", ""))
                elif resp.status_code == 200:
                    ws_data = resp.json()
                    ws_next = ws_data.get("continue_url", "")
                    ws_page = ws_data.get("page", {}).get("type", "")

                    # 4c: organization/select
                    if "organization" in ws_next or "organization" in ws_page:
                        org_id = None
                        project_id = None
                        ws_orgs = ws_data.get("data", {}).get("orgs", [])
                        if ws_orgs:
                            org_id = ws_orgs[0].get("id")
                            projects = ws_orgs[0].get("projects", [])
                            if projects:
                                project_id = projects[0].get("id")

                        if org_id:
                            emitter.info("[登录] [4c] POST organization/select ...", step="consent")
                            body = {"org_id": org_id}
                            if project_id:
                                body["project_id"] = project_id

                            h_org = dict(COMMON_HEADERS)
                            h_org["referer"] = ws_next if ws_next.startswith("http") else f"{AUTH_BASE}{ws_next}"
                            h_org["oai-device-id"] = login_device_id
                            h_org.update(_generate_datadog_trace())

                            resp = login_session.post(
                                f"{AUTH_BASE}/api/accounts/organization/select",
                                json=body, headers=h_org,
                                verify=False, timeout=30, allow_redirects=False,
                            )

                            if resp.status_code in (301, 302, 303, 307, 308):
                                loc = resp.headers.get("Location", "")
                                auth_code = _extract_code_from_url(loc)
                                if not auth_code:
                                    auth_code = _follow_and_extract_code(login_session, loc)
                            elif resp.status_code == 200:
                                org_data = resp.json()
                                org_next = org_data.get("continue_url", "")
                                if org_next:
                                    full_next = org_next if org_next.startswith("http") else f"{AUTH_BASE}{org_next}"
                                    auth_code = _follow_and_extract_code(login_session, full_next)
                        else:
                            org_url = ws_next if ws_next.startswith("http") else f"{AUTH_BASE}{ws_next}"
                            auth_code = _follow_and_extract_code(login_session, org_url)
                    elif ws_next:
                        full_next = ws_next if ws_next.startswith("http") else f"{AUTH_BASE}{ws_next}"
                        auth_code = _follow_and_extract_code(login_session, full_next)
            except Exception as e:
                emitter.warn(f"[登录] workspace/select 异常: {e}", step="consent")

    # 4d: 备用策略
    if not auth_code:
        emitter.info("[登录] [4d] 备用策略 allow_redirects=True ...", step="consent")
        try:
            resp = login_session.get(consent_url, headers=NAVIGATE_HEADERS,
                                     verify=False, timeout=30, allow_redirects=True)
            auth_code = _extract_code_from_url(resp.url)
            if not auth_code and resp.history:
                for r in resp.history:
                    loc = r.headers.get("Location", "")
                    auth_code = _extract_code_from_url(loc)
                    if auth_code:
                        break
        except requests.exceptions.ConnectionError as e:
            url_match = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if url_match:
                auth_code = _extract_code_from_url(url_match.group(1))
        except Exception as e:
            emitter.warn(f"[登录] 备用策略异常: {e}", step="consent")

    if not auth_code:
        emitter.error("[登录] 未获取到 authorization code", step="consent")
        return None

    emitter.success(f"[登录] 获取到 code (长度: {len(auth_code)})", step="consent")

    # ===== 换 Token =====
    emitter.info("[登录] POST /oauth/token 换取 Token ...", step="get_token")

    token_session = _create_session(proxy_str)
    for attempt in range(2):
        try:
            resp = token_session.post(
                f"{AUTH_BASE}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": DEFAULT_REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "code_verifier": login_verifier,
                },
                verify=False,
                timeout=60,
            )
            break
        except Exception as e:
            if attempt == 0:
                emitter.warn("[登录] Token 交换超时，重试...", step="get_token")
                time.sleep(2)
                continue
            emitter.error(f"[登录] Token 交换失败: {e}", step="get_token")
            return None

    if resp.status_code != 200:
        emitter.error(f"[登录] Token 交换失败: HTTP {resp.status_code} {_response_preview(resp)}", step="get_token")
        return None

    token_data = resp.json()
    at_len = len(token_data.get("access_token", ""))
    has_rt = bool(token_data.get("refresh_token"))
    emitter.success(f"[登录] Token 获取成功 (AT长度: {at_len}, RT: {has_rt})", step="get_token")
    return token_data


# =================== 主流程 ===================


def run_v3(
    proxy: Optional[str],
    emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    mail_provider=None,
    proxy_pool_config: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    V3 纯协议注册流程（完整移植 codexgen 逻辑）

    流程：
    第一阶段 - 注册：
      1. 创建邮箱
      2. OAuth 初始化（screen_hint=signup）
      3. 提交邮箱（authorize/continue + sentinel）
      4. 注册用户（user/register + sentinel）
      5. 触发+验证 OTP（双候选 URL）
      6. 创建账号（about-you 双候选策略）
    第二阶段 - 登录换 Token：
      7. 新 session 登录 → consent → code → token
    """

    proxy_str = _normalize_proxy_value(proxy)

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    try:
        # ========== 第一阶段：注册 ==========

        # 步骤1: 创建邮箱
        emitter.info("创建临时邮箱...", step="create_email")
        if not mail_provider:
            emitter.error("未提供邮箱提供商", step="create_email")
            return None

        try:
            provider_name = str(
                getattr(mail_provider, "provider_name", "")
                or getattr(mail_provider, "name", "")
                or emitter._defaults.get("mail_provider")
                or ""
            ).strip()
            email, otp_token = mail_provider.create_mailbox(
                proxy=proxy_str,
            )
        except TypeError:
            email, otp_token = mail_provider.create_mailbox(proxy_str)
        if not email:
            emitter.error("邮箱创建失败", step="create_email")
            return None
        emitter.success(f"邮箱: {email}", step="create_email")

        # 生成密码
        password = _generate_random_password()

        if _stopped():
            return None

        # 创建注册 session
        session = _create_session(proxy_str)
        device_id = _generate_device_id()

        # 步骤2: OAuth 初始化（screen_hint=signup）
        emitter.info("OAuth 会话初始化...", step="oauth_init")

        # 设置 oai-did cookie（两个 domain）
        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
        session.cookies.set("oai-did", device_id, domain="auth.openai.com")

        # PKCE
        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(32)

        authorize_params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": DEFAULT_REDIRECT_URI,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "screen_hint": "signup",
            "prompt": "login",
        }
        authorize_url = f"{AUTH_BASE}/oauth/authorize?{urlencode(authorize_params)}"

        try:
            resp = session.get(
                authorize_url,
                headers=NAVIGATE_HEADERS,
                allow_redirects=True,
                verify=False,
                timeout=30,
            )
        except Exception as e:
            emitter.error(f"OAuth 授权请求失败: {e}", step="oauth_init")
            return None

        has_login_session = any(c.name == "login_session" for c in session.cookies)
        if not has_login_session:
            emitter.error("未获得 login_session cookie", step="oauth_init")
            return None

        emitter.success(f"OAuth 初始化完成 (device_id: {device_id[:8]}...)", step="oauth_init")

        if _stopped():
            return None

        # 步骤3: 提交邮箱（authorize/continue + sentinel）
        emitter.info("提交注册邮箱...", step="signup")

        sentinel_token = _build_sentinel_token(session, device_id, flow="authorize_continue")
        if not sentinel_token:
            emitter.error("无法获取 authorize_continue sentinel token", step="sentinel")
            return None

        headers = _build_api_headers(device_id, f"{AUTH_BASE}/create-account",
                                     with_sentinel=True, sentinel_token_str=sentinel_token)

        try:
            resp = session.post(
                f"{AUTH_BASE}/api/accounts/authorize/continue",
                json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"},
                headers=headers,
                verify=False,
                timeout=30,
            )
        except Exception as e:
            emitter.error(f"邮箱提交失败: {e}", step="signup")
            return None

        if resp.status_code != 200:
            emitter.error(f"邮箱提交失败: HTTP {resp.status_code} {_response_preview(resp)}", step="signup")
            return None

        page_type = ""
        try:
            data = resp.json()
            page_type = data.get("page", {}).get("type", "")
        except Exception:
            pass
        emitter.success(f"邮箱提交成功 -> {page_type}", step="signup")

        if _stopped():
            return None

        # 步骤4: 注册用户（user/register + sentinel）
        emitter.info("注册用户...", step="register")

        sentinel_reg = _build_sentinel_token(session, device_id, flow="authorize_continue")
        headers = _build_api_headers(device_id, f"{AUTH_BASE}/create-account/password",
                                     with_sentinel=True, sentinel_token_str=sentinel_reg)

        try:
            resp = session.post(
                f"{AUTH_BASE}/api/accounts/user/register",
                json={"username": email, "password": password},
                headers=headers,
                verify=False,
                timeout=30,
            )
        except Exception as e:
            emitter.error(f"用户注册失败: {e}", step="register")
            return None

        if resp.status_code != 200:
            # 某些 302 重定向也算成功
            if resp.status_code in (301, 302):
                redirect_url = resp.headers.get('Location', '')
                if 'email-otp' not in redirect_url and 'email-verification' not in redirect_url:
                    emitter.error(f"用户注册失败: HTTP {resp.status_code} {_response_preview(resp)}", step="register")
                    return None
            else:
                emitter.error(f"用户注册失败: HTTP {resp.status_code} {_response_preview(resp)}", step="register")
                return None

        emitter.success("用户注册成功", step="register")

        if _stopped():
            return None

        time.sleep(1)

        # 步骤5: 触发 OTP 发送 + resend 重试
        emitter.info("触发验证码发送...", step="send_otp")

        # 5a: GET send 端点（初始触发）
        h_send = dict(NAVIGATE_HEADERS)
        h_send["referer"] = f"{AUTH_BASE}/create-account/password"
        session.get(f"{AUTH_BASE}/api/accounts/email-otp/send", headers=h_send,
                    verify=False, timeout=30, allow_redirects=True)

        # 5b: GET email-verification 页面
        h_verify = dict(NAVIGATE_HEADERS)
        h_verify["referer"] = f"{AUTH_BASE}/create-account/password"
        session.get(f"{AUTH_BASE}/email-verification", headers=h_verify,
                    verify=False, timeout=30, allow_redirects=True)

        emitter.success("验证码发送触发完成", step="send_otp")

        # 等待 OTP（初始等待 120s + resend 重试 45/90/120s）
        emitter.info("等待验证码...", step="wait_otp")
        otp_code = ""
        wait_rounds = [120, 45, 90, 120]  # 初始120s, resend后45s, 再resend后90s, 最后120s

        for attempt, wait_sec in enumerate(wait_rounds):
            if _stopped():
                return None

            # 第1轮是初始等待，后续轮次先 resend 再等待
            if attempt > 0:
                emitter.info(f"未收到验证码，第 {attempt} 次 resend...", step="send_otp")
                h_resend = dict(COMMON_HEADERS)
                h_resend["referer"] = f"{AUTH_BASE}/email-verification"
                h_resend["oai-device-id"] = device_id
                h_resend.update(_generate_datadog_trace())
                sentinel_resend = _build_sentinel_token(session, device_id, flow="authorize_continue")
                if sentinel_resend:
                    h_resend["openai-sentinel-token"] = sentinel_resend
                try:
                    resp_resend = session.post(
                        f"{AUTH_BASE}/api/accounts/email-otp/resend",
                        headers=h_resend, json={},
                        verify=False, timeout=30,
                    )
                    emitter.info(f"resend 响应: HTTP {resp_resend.status_code}", step="send_otp")
                except Exception as e:
                    emitter.warn(f"resend 请求失败: {e}", step="send_otp")

            try:
                otp_code = mail_provider.wait_for_otp(
                    otp_token, email, proxy=proxy_str, stop_event=stop_event,
                    timeout=wait_sec,
                )
            except TypeError:
                otp_code = mail_provider.wait_for_otp(
                    otp_token, email, proxy=proxy_str,
                    timeout=wait_sec,
                )

            if otp_code:
                break

        if not otp_code:
            emitter.error("未收到验证码（已重试 resend）", step="wait_otp")
            return None

        emitter.success(f"验证码: {otp_code}", step="wait_otp")

        if _stopped():
            return None

        # 步骤6: 验证 OTP（双候选 URL）
        emitter.info("验证 OTP...", step="verify_otp")

        sentinel_otp = _build_sentinel_token(session, device_id, flow="authorize_continue")
        candidates = [
            (
                f"{AUTH_BASE}/api/accounts",
                f"{AUTH_BASE}/email-verification",
                {"origin_page_type": "email_otp_verification", "data": {"intent": "validate", "code": otp_code}},
            ),
            (
                f"{AUTH_BASE}/api/accounts/email-otp/validate",
                f"{AUTH_BASE}/email-verification",
                {"code": otp_code},
            ),
        ]

        otp_verified = False
        last_error = "未发起请求"
        for url, referer, payload in candidates:
            headers = dict(COMMON_HEADERS)
            headers["referer"] = referer
            headers["oai-device-id"] = device_id
            headers.update(_generate_datadog_trace())
            if sentinel_otp:
                headers["openai-sentinel-token"] = sentinel_otp

            try:
                resp = session.post(url, headers=headers, data=json.dumps(payload, separators=(",", ":")),
                                    verify=False, timeout=30)
            except Exception as exc:
                last_error = f"{url}: {exc}"
                continue

            if resp.status_code == 200:
                otp_verified = True
                break

            err_code = _extract_openai_error_code(resp)
            last_error = f"HTTP {resp.status_code} {_response_preview(resp)}"
            if err_code:
                last_error += f" [code={err_code}]"

        if not otp_verified:
            emitter.error(f"OTP 验证失败: {last_error}", step="verify_otp")
            return None

        emitter.success("OTP 验证成功", step="verify_otp")

        if _stopped():
            return None

        time.sleep(1)

        # 步骤7: 创建账号（about-you 双候选策略）
        emitter.info("创建账号信息...", step="create_account")
        first_name, last_name = _generate_random_name()
        name = f"{first_name} {last_name}"
        birthdate = _generate_random_birthday()

        continue_url = _complete_about_you(session, device_id, name, birthdate, emitter)
        if continue_url is None:
            return None

        emitter.success(f"账号创建完成 (continue_url: {continue_url[:80] if continue_url else 'empty'})", step="create_account")

        if _stopped():
            return None

        # ========== 第二阶段：获取 Token ==========

        time.sleep(random.uniform(1.0, 2.0))

        # 优先走 session fast path（从 create_account 的 continue_url 直接拿 token）
        token_json = None
        if continue_url:
            token_json = _session_fast_path(
                session=session,
                continue_url=continue_url,
                email=email,
                password=password,
                proxy_str=proxy_str,
                emitter=emitter,
            )

        # fast path 失败，fallback 到旧的登录换 Token 流程
        if not token_json:
            emitter.info("fast path 不可用，fallback 到登录换 Token...", step="get_token")

            time.sleep(random.uniform(1.0, 3.0))

            token_data = _perform_login(
                session=session,
                email=email,
                password=password,
                device_id=device_id,
                code_verifier=code_verifier,
                emitter=emitter,
                mail_provider=mail_provider,
                otp_token=otp_token,
                proxy_str=proxy_str,
                stop_event=stop_event,
                used_otp_codes={otp_code},
            )

            if not token_data:
                emitter.error("登录换 Token 失败", step="get_token")
                return None

            emitter.info("保存 Token...", step="save_token")
            try:
                token_json = _build_token_result(token_data, account_password=password)
            except Exception as e:
                emitter.error(f"Token 构建失败: {e}", step="save_token")
                return None

        # 保存文件
        emitter.info("保存 Token...", step="save_token")
        token_obj = json.loads(token_json)
        token_obj["mail_provider"] = provider_name
        token_obj["mail_credential"] = otp_token
        token_json = json.dumps(token_obj, ensure_ascii=False, separators=(",", ":"))
        account_email = token_obj.get("email", email)
        safe_name = re.sub(r'[^\w@.\-]', '_', account_email)
        filename = f"{safe_name}.json"
        filepath = os.path.join(TOKENS_DIR, filename)
        os.makedirs(TOKENS_DIR, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(token_json)

        emitter.success(f"Token 保存成功: {filename}", step="save_token")
        return token_json

    except Exception as e:
        emitter.error(f"注册异常: {e}", step="runtime")
        import traceback
        traceback.print_exc()
        return None


def main():
    """CLI 入口"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="OpenAI 账号注册工具 (V3 纯协议版)")
    parser.add_argument("--proxy", type=str, default="", help="代理地址")
    parser.add_argument("--once", action="store_true", help="单次注册后退出")
    args = parser.parse_args()

    config_path = os.path.join(os.path.dirname(__file__), "..", "data", "sync_config.json")
    if not os.path.exists(config_path):
        print(f"配置文件不存在: {config_path}")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

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

    proxy_val = args.proxy or config.get("proxy", "")

    if args.once:
        result = run_v3(proxy_val, mail_provider=router)
        sys.exit(0 if result else 1)
    else:
        while True:
            run_v3(proxy_val, mail_provider=router)
            time.sleep(random.randint(5, 10))


if __name__ == "__main__":
    main()
