from __future__ import annotations

import secrets
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from .base import MailProvider
from .common import build_session, extract_code, logger


class DuckMailProvider(MailProvider):
    def __init__(self, api_base: str = "https://api.duckmail.sbs", bearer_token: str = ""):
        self.api_base = api_base.rstrip("/")
        self.bearer_token = bearer_token

    def _auth_headers(self, token: str = "") -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def create_mailbox(
        self,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
    ) -> Tuple[str, str]:
        with build_session(proxy, proxy_selector) as session:
            headers: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
            if self.bearer_token:
                headers["Authorization"] = f"Bearer {self.bearer_token}"
            try:
                domains_resp = session.get(
                    f"{self.api_base}/domains",
                    headers={"Accept": "application/json"},
                    timeout=15,
                    verify=False,
                )
                if domains_resp.status_code != 200:
                    return "", ""
                data = domains_resp.json()
                items = data if isinstance(data, list) else (data.get("hydra:member") or [])
                domains = [
                    str(item.get("domain") or "")
                    for item in items
                    if isinstance(item, dict) and item.get("domain") and item.get("isActive", True)
                ]
                if not domains:
                    return "", ""
                preferred = [domain for domain in domains if "duckmail" in domain.lower()]
                domain = preferred[0] if preferred else domains[0]
                local = f"oc{secrets.token_hex(5)}"
                email = f"{local}@{domain}"
                password = secrets.token_urlsafe(18)
                resp = session.post(
                    f"{self.api_base}/accounts",
                    json={"address": email, "password": password},
                    headers=headers,
                    timeout=30,
                    verify=False,
                )
                if resp.status_code not in (200, 201):
                    return "", ""
                time.sleep(0.5)
                token_resp = session.post(
                    f"{self.api_base}/token",
                    json={"address": email, "password": password},
                    headers=headers,
                    timeout=30,
                    verify=False,
                )
                if token_resp.status_code == 200:
                    mail_token = token_resp.json().get("token")
                    if mail_token:
                        return email, str(mail_token)
            except Exception as exc:
                logger.warning("DuckMail 创建邮箱失败: %s", exc)
        return "", ""

    def wait_for_otp(
        self,
        auth_credential: str,
        email: str,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
        timeout: int = 120,
        stop_event: Optional[threading.Event] = None,
    ) -> str:
        with build_session(proxy, proxy_selector) as session:
            seen_ids: set = set()
            start = time.time()
            while time.time() - start < timeout:
                if stop_event and stop_event.is_set():
                    return ""
                try:
                    resp = session.get(
                        f"{self.api_base}/messages",
                        headers=self._auth_headers(auth_credential),
                        timeout=30,
                        verify=False,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        messages = data.get("hydra:member") or data.get("member") or data.get("data") or []
                        for msg in (messages if isinstance(messages, list) else []):
                            if not isinstance(msg, dict):
                                continue
                            msg_id = msg.get("id") or msg.get("@id")
                            if not msg_id or msg_id in seen_ids:
                                continue
                            raw_id = str(msg_id).split("/")[-1] if str(msg_id).startswith("/") else str(msg_id)
                            detail_resp = session.get(
                                f"{self.api_base}/messages/{raw_id}",
                                headers=self._auth_headers(auth_credential),
                                timeout=30,
                                verify=False,
                            )
                            if detail_resp.status_code == 200:
                                seen_ids.add(msg_id)
                                detail = detail_resp.json()
                                content = detail.get("text") or detail.get("html") or ""
                                code = extract_code(content)
                                if code:
                                    return code
                except Exception as exc:
                    logger.warning("DuckMail 轮询验证码失败: %s", exc)
                time.sleep(3)
        return ""
