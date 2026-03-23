from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Optional, Tuple

from .base import MailProvider
from .common import build_session, extract_code, logger, random_mail_prefix


class MoeMailProvider(MailProvider):
    def __init__(self, api_base: str, api_key: str):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        return {"X-API-Key": self.api_key}

    def _get_domain(self, session) -> Optional[str]:
        try:
            resp = session.get(
                f"{self.api_base}/api/config",
                headers=self._headers(),
                timeout=10,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                domains_str = data.get("emailDomains", "")
                if domains_str:
                    domains = [item.strip() for item in domains_str.split(",") if item.strip()]
                    if domains:
                        return domains[0]
        except Exception as exc:
            logger.warning("MoeMail 读取域名配置失败: %s", exc)
        return None

    def create_mailbox(
        self,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
    ) -> Tuple[str, str]:
        with build_session(proxy, proxy_selector) as session:
            domain = self._get_domain(session)
            if not domain:
                return "", ""
            prefix = random_mail_prefix()
            try:
                resp = session.post(
                    f"{self.api_base}/api/emails/generate",
                    json={"name": prefix, "domain": domain, "expiryTime": 0},
                    headers=self._headers(),
                    timeout=15,
                    verify=False,
                )
                if resp.status_code not in (200, 201):
                    return "", ""
                data = resp.json()
                email_id = data.get("id")
                email = data.get("email")
                if email_id and email:
                    return email, str(email_id)
            except Exception as exc:
                logger.warning("MoeMail 创建邮箱失败: %s", exc)
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
            email_id = auth_credential
            start = time.time()
            while time.time() - start < timeout:
                if stop_event and stop_event.is_set():
                    return ""
                try:
                    resp = session.get(
                        f"{self.api_base}/api/emails/{email_id}",
                        headers=self._headers(),
                        timeout=15,
                        verify=False,
                    )
                    if resp.status_code == 200:
                        messages = resp.json().get("messages") or []
                        for msg in messages:
                            if not isinstance(msg, dict):
                                continue
                            msg_id = msg.get("id")
                            if not msg_id:
                                continue
                            detail_resp = session.get(
                                f"{self.api_base}/api/emails/{email_id}/{msg_id}",
                                headers=self._headers(),
                                timeout=15,
                                verify=False,
                            )
                            if detail_resp.status_code == 200:
                                detail = detail_resp.json()
                                msg_obj = detail.get("message") or {}
                                content = msg_obj.get("content") or msg_obj.get("html") or ""
                                if not content:
                                    content = detail.get("text") or detail.get("html") or ""
                                code = extract_code(content)
                                if code:
                                    return code
                except Exception as exc:
                    logger.warning("MoeMail 轮询验证码失败: %s", exc)
                time.sleep(3)
        return ""
