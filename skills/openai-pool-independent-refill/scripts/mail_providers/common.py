from __future__ import annotations

import logging
import random
import re
import secrets
import string
import threading
import time
from email import policy
from typing import Any, Callable, Dict, List, Optional

import requests as _requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)
urllib3.disable_warnings(InsecureRequestWarning)


def normalize_proxy_url(proxy: str) -> str:
    value = str(proxy or "").strip()
    if not value:
        return ""
    if "://" in value:
        return value
    if ":" in value:
        return f"http://{value}"
    return ""


class ProxyAwareSession(_requests.Session):
    def __init__(
        self,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
    ):
        super().__init__()
        self._default_proxy = normalize_proxy_url(proxy)
        self._proxy_selector = proxy_selector

    def request(self, method, url, **kwargs):
        selected_proxy = ""
        if self._proxy_selector:
            try:
                selected_proxy = normalize_proxy_url(self._proxy_selector() or "")
            except Exception:
                selected_proxy = ""
        if not selected_proxy:
            selected_proxy = self._default_proxy
        base_kwargs = dict(kwargs)
        if selected_proxy and "proxies" not in base_kwargs:
            base_kwargs["proxies"] = {"http": selected_proxy, "https": selected_proxy}
        try:
            return super().request(method, url, **base_kwargs)
        except Exception:
            if (
                selected_proxy
                and self._default_proxy
                and selected_proxy != self._default_proxy
                and "proxies" not in kwargs
            ):
                fallback_kwargs = dict(kwargs)
                fallback_kwargs["proxies"] = {"http": self._default_proxy, "https": self._default_proxy}
                return super().request(method, url, **fallback_kwargs)
            raise


def build_session(proxy: str = "", proxy_selector: Optional[Callable[[], str]] = None) -> _requests.Session:
    session = ProxyAwareSession(proxy, proxy_selector)
    retry_total = 0 if proxy_selector else 2
    retry = Retry(
        total=retry_total,
        connect=retry_total,
        read=retry_total,
        status=retry_total,
        backoff_factor=0.2,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    fixed_proxy = normalize_proxy_url(proxy)
    if fixed_proxy and not proxy_selector:
        session.proxies = {"http": fixed_proxy, "https": fixed_proxy}
    return session


def extract_code(content: str) -> Optional[str]:
    if not content:
        return None
    match = re.search(r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>", content)
    if match:
        return match.group(1)
    patterns = [
        r"Verification code:?\s*(\d{6})",
        r"code is\s*(\d{6})",
        r"Subject:.*?(\d{6})",
        r">\s*(\d{6})\s*<",
        r"(?<![#&])\b(\d{6})\b",
    ]
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for code in matches:
            return code
    return None


def parse_raw_email_content(raw: str) -> str:
    try:
        import email as _email_mod

        parsed = _email_mod.message_from_string(raw, policy=policy.default)
        body = parsed.get_body(preferencelist=("plain", "html"))
        if body:
            content = body.get_content() or ""
            if content:
                return str(content)
        for part in parsed.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                payload = part.get_content()
                if payload:
                    return str(payload)
    except Exception as exc:
        logger.warning("解析原始邮件失败: %s", exc)
    return raw


def random_mail_prefix(min_len: int = 8, max_len: int = 13) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(random.randint(min_len, max_len)))


def random_duck_style_name() -> str:
    return f"oc{secrets.token_hex(5)}"
