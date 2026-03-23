from __future__ import annotations

import random
import secrets
import uuid
from http.cookiejar import CookieJar
from typing import Any, Dict, Mapping
from urllib.parse import urlparse

from curl_cffi import requests

_CHROME_PROFILES = [
    {
        "major": 119,
        "impersonate": "chrome119",
        "build": 6045,
        "patch": (123, 200),
        "sec": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
    },
    {
        "major": 120,
        "impersonate": "chrome120",
        "build": 6099,
        "patch": (62, 200),
        "sec": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    },
    {
        "major": 123,
        "impersonate": "chrome123",
        "build": 6312,
        "patch": (46, 170),
        "sec": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
    },
    {
        "major": 124,
        "impersonate": "chrome124",
        "build": 6367,
        "patch": (60, 180),
        "sec": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    },
]
DEFAULT_TIMEOUT = 15


def _build_browser_profile() -> Dict[str, str]:
    profile = random.choice(_CHROME_PROFILES)
    chrome_full = f"{profile['major']}.0.{profile['build']}.{random.randint(*profile['patch'])}"
    return {
        "impersonate": str(profile["impersonate"]),
        "user_agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_full} Safari/537.36",
        "accept_language": random.choice(["en-US,en;q=0.9", "en-US,en;q=0.9,zh-CN;q=0.8", "en,en-US;q=0.9"]),
        "sec_ch_ua": str(profile["sec"]),
        "sec_ch_ua_full_version": f'"{chrome_full}"',
        "sec_ch_ua_platform_version": f'"{random.randint(10, 15)}.0.0"',
    }


def build_trace_headers() -> Dict[str, str]:
    trace_id = random.randint(10**17, 10**18 - 1)
    parent_id = random.randint(10**17, 10**18 - 1)
    traceparent = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
    return {
        "traceparent": traceparent,
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(trace_id),
        "x-datadog-parent-id": str(parent_id),
    }


class RegisterHttpClient:
    def __init__(
        self,
        proxy: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
        timeout: int | float = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ):
        browser_profile = _build_browser_profile()
        self.proxy = (proxy or "").strip()
        self.timeout = timeout
        self.impersonate = str(browser_profile["impersonate"])
        self.session = session or requests.Session(impersonate=self.impersonate)
        self._device_id: str | None = None
        self.session.headers.update({
            "User-Agent": user_agent or str(browser_profile["user_agent"]),
            "Accept-Language": accept_language or str(browser_profile["accept_language"]),
            "Accept": "*/*",
            "sec-ch-ua": str(browser_profile["sec_ch_ua"]),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": str(browser_profile["sec_ch_ua_full_version"]),
            "sec-ch-ua-platform-version": str(browser_profile["sec_ch_ua_platform_version"]),
        })
        if self.proxy:
            self.session.proxies.update({"http": self.proxy, "https": self.proxy})

    @property
    def cookie_jar(self) -> CookieJar:
        return self.session.cookies

    @property
    def user_agent(self) -> str:
        return str(self.session.headers.get("User-Agent") or "")

    def ensure_device_id(self) -> str:
        existing = self.get_cookie("oai-did", domain="auth.openai.com") or self.get_cookie("oai-did", domain="chatgpt.com") or self.get_cookie("oai-did")
        if existing:
            self._device_id = existing
            return existing
        if self._device_id:
            self.set_cookie("oai-did", self._device_id, domain="auth.openai.com")
            return self._device_id
        self._device_id = secrets.token_hex(16)
        self.set_cookie("oai-did", self._device_id, domain="auth.openai.com")
        return self._device_id

    def trace_headers(self) -> Dict[str, str]:
        return build_trace_headers()

    def get_cookie(self, name: str, default: str | None = None, domain: str | None = None) -> str | None:
        try:
            if domain:
                value = self.session.cookies.get(name, domain=domain)
            else:
                value = self.session.cookies.get(name)
        except Exception:
            for cookie in self.session.cookies:
                cookie_name = str(getattr(cookie, "name", "") or "")
                cookie_domain = str(getattr(cookie, "domain", "") or "")
                if cookie_name != name:
                    continue
                if domain and domain not in cookie_domain and cookie_domain not in domain:
                    continue
                value = getattr(cookie, "value", None)
                break
            else:
                value = None
        if value is None:
            return default
        return str(value)

    def set_cookie(
        self,
        name: str,
        value: str,
        *,
        domain: str | None = None,
        path: str = "/",
    ) -> None:
        cookie_domain = domain or "auth.openai.com"
        self.session.cookies.set(name, value, domain=cookie_domain, path=path)
        if name == "oai-did":
            self._device_id = value

    def default_headers(
        self,
        url: str = "",
        *,
        referer: str | None = None,
        origin: str | None = None,
        trace: bool = False,
        headers: Mapping[str, Any] | None = None,
    ) -> Dict[str, str]:
        merged = dict(self.session.headers)
        if referer:
            merged["Referer"] = referer
        if origin:
            merged["Origin"] = origin
        elif referer:
            parsed = urlparse(referer)
            if parsed.scheme and parsed.netloc:
                merged["Origin"] = f"{parsed.scheme}://{parsed.netloc}"
        if trace:
            merged.update(self.trace_headers())
        if headers:
            merged.update({str(k): str(v) for k, v in headers.items()})
        return merged

    def _request(self, method: str, url: str, **kwargs: Any):
        request_kwargs = dict(kwargs)
        request_kwargs.setdefault("timeout", self.timeout)
        request_kwargs.setdefault("allow_redirects", True)
        request_kwargs.setdefault("headers", self.default_headers(url))
        request_kwargs.setdefault("impersonate", self.impersonate)
        request_kwargs.setdefault("http_version", 2)
        if self.proxy and "proxies" not in request_kwargs:
            request_kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        return self.session.request(method.upper(), url, **request_kwargs)

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, Any] | None = None,
        referer: str | None = None,
        origin: str | None = None,
        trace: bool = False,
        **kwargs: Any,
    ):
        merged_headers = self.default_headers(
            url,
            referer=referer,
            origin=origin,
            trace=trace,
            headers=headers,
        )
        return self._request("GET", url, headers=merged_headers, **kwargs)

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, Any] | None = None,
        referer: str | None = None,
        origin: str | None = None,
        trace: bool = False,
        **kwargs: Any,
    ):
        merged_headers = self.default_headers(
            url,
            referer=referer,
            origin=origin,
            trace=trace,
            headers=headers,
        )
        return self._request("POST", url, headers=merged_headers, **kwargs)
