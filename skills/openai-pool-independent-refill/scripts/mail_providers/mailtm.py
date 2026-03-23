from __future__ import annotations

import random
import secrets
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from .base import MailProvider
from .common import build_session, extract_code, logger


class MailTmProvider(MailProvider):
    def __init__(self, api_base: str = "https://api.mail.tm"):
        self.api_base = api_base.rstrip("/")

    def _headers(self, token: str = "", use_json: bool = False) -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if use_json:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _get_domains(self, session) -> List[str]:
        resp = session.get(f"{self.api_base}/domains", headers=self._headers(), timeout=15, verify=False)
        if resp.status_code != 200:
            return []
        data = resp.json()
        items = data if isinstance(data, list) else (data.get("hydra:member") or data.get("items") or [])
        domains = []
        for item in items:
            if not isinstance(item, dict):
                continue
            domain = str(item.get("domain") or "").strip()
            if domain and item.get("isActive", True) and not item.get("isPrivate", False):
                domains.append(domain)
        return domains

    def create_mailbox(
        self,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
    ) -> Tuple[str, str]:
        with build_session(proxy, proxy_selector) as session:
            domains = self._get_domains(session)
            if not domains:
                return "", ""
            preferred = [domain for domain in domains if "duckmail" in domain.lower()]
            domain = random.choice(preferred) if preferred else random.choice(domains)
            for _ in range(5):
                local = f"oc{secrets.token_hex(5)}"
                email = f"{local}@{domain}"
                password = secrets.token_urlsafe(18)
                resp = session.post(
                    f"{self.api_base}/accounts",
                    headers=self._headers(use_json=True),
                    json={"address": email, "password": password},
                    timeout=15,
                    verify=False,
                )
                if resp.status_code not in (200, 201):
                    continue
                token_resp = session.post(
                    f"{self.api_base}/token",
                    headers=self._headers(use_json=True),
                    json={"address": email, "password": password},
                    timeout=15,
                    verify=False,
                )
                if token_resp.status_code == 200:
                    token = str(token_resp.json().get("token") or "").strip()
                    if token:
                        return email, token
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
            seen_ids: set[str] = set()
            start = time.time()
            while time.time() - start < timeout:
                if stop_event and stop_event.is_set():
                    return ""
                try:
                    resp = session.get(
                        f"{self.api_base}/messages",
                        headers=self._headers(token=auth_credential),
                        timeout=15,
                        verify=False,
                    )
                    if resp.status_code != 200:
                        time.sleep(3)
                        continue
                    data = resp.json()
                    messages = data if isinstance(data, list) else (data.get("hydra:member") or data.get("messages") or [])
                    for msg in messages:
                        if not isinstance(msg, dict):
                            continue
                        msg_id = str(msg.get("id") or msg.get("@id") or "").strip()
                        if not msg_id or msg_id in seen_ids:
                            continue
                        if msg_id.startswith("/messages/"):
                            msg_id = msg_id.split("/")[-1]
                        detail_resp = session.get(
                            f"{self.api_base}/messages/{msg_id}",
                            headers=self._headers(token=auth_credential),
                            timeout=15,
                            verify=False,
                        )
                        if detail_resp.status_code != 200:
                            continue
                        seen_ids.add(msg_id)
                        mail_data = detail_resp.json()
                        sender = str(((mail_data.get("from") or {}).get("address") or "")).lower()
                        subject = str(mail_data.get("subject") or "")
                        intro = str(mail_data.get("intro") or "")
                        text = str(mail_data.get("text") or "")
                        html = mail_data.get("html") or ""
                        if isinstance(html, list):
                            html = "\n".join(str(item) for item in html)
                        content = "\n".join([subject, intro, text, str(html)])
                        if "openai" not in sender and "openai" not in content.lower():
                            continue
                        code = extract_code(content)
                        if code:
                            return code
                except Exception as exc:
                    logger.warning("Mail.tm 轮询验证码失败: %s", exc)
                time.sleep(3)
        return ""
