from __future__ import annotations

import random
import string
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .base import MailProvider
from .common import build_session, extract_code, logger, parse_raw_email_content


class CloudflareTempEmailProvider(MailProvider):
    def __init__(self, api_base: str = "", admin_password: str = "", domain: str = ""):
        self.api_base = api_base.rstrip("/")
        self.admin_password = admin_password
        self.domain = str(domain).strip()
        self._tls = threading.local()

    def _get_random_domain(self) -> str:
        if not self.domain:
            return ""
        if self.domain.startswith("[") and self.domain.endswith("]"):
            try:
                import json
                domain_list = json.loads(self.domain)
                if isinstance(domain_list, list) and domain_list:
                    choices = [str(item).strip() for item in domain_list if str(item).strip()]
                    if choices:
                        return random.choice(choices)
            except Exception:
                pass
        if "," in self.domain:
            parts = [item.strip() for item in self.domain.split(",") if item.strip()]
            if parts:
                return random.choice(parts)
        return self.domain

    @staticmethod
    def _message_matches_email(msg: Dict[str, Any], target_email: str) -> bool:
        target = str(target_email or "").strip().lower()
        if not target:
            return True

        def _extract_text_candidates(value: Any) -> List[str]:
            output: List[str] = []
            if isinstance(value, str):
                output.append(value)
            elif isinstance(value, dict):
                for key in ("address", "email", "name", "value"):
                    if value.get(key):
                        output.extend(_extract_text_candidates(value.get(key)))
            elif isinstance(value, list):
                for item in value:
                    output.extend(_extract_text_candidates(item))
            return output

        candidates: List[str] = []
        for key in ("to", "mailTo", "receiver", "receivers", "address", "email", "envelope_to"):
            if key in msg:
                candidates.extend(_extract_text_candidates(msg.get(key)))
        if not candidates:
            return True
        target_lower = target.lower()
        for raw in candidates:
            text = str(raw or "").strip().lower()
            if text and target_lower in text:
                return True
        return False

    def create_mailbox(
        self,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
    ) -> Tuple[str, str]:
        if not self.api_base or not self.admin_password or not self.domain:
            return "", ""
        with build_session(proxy, proxy_selector) as session:
            try:
                letters1 = "".join(random.choices(string.ascii_lowercase, k=5))
                numbers = "".join(random.choices(string.digits, k=random.randint(1, 3)))
                letters2 = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
                name = letters1 + numbers + letters2
                target_domain = self._get_random_domain()
                if not target_domain:
                    return "", ""
                resp = session.post(
                    f"{self.api_base}/admin/new_address",
                    json={
                        "enablePrefix": True,
                        "name": name,
                        "domain": target_domain,
                    },
                    headers={
                        "x-admin-auth": self.admin_password,
                        "Content-Type": "application/json",
                    },
                    timeout=30,
                    verify=False,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    email = data.get("address")
                    jwt_token = data.get("jwt")
                    if email and jwt_token:
                        self._tls.jwt_token = jwt_token
                        return email, jwt_token
            except Exception as exc:
                logger.warning("Cloudflare 临时邮箱创建失败: %s", exc)
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
        token = str(auth_credential or "").strip() or str(getattr(self._tls, "jwt_token", "") or "").strip()
        if not token:
            return ""
        with build_session(proxy, proxy_selector) as session:
            seen_ids: set = set()
            start = time.time()
            while time.time() - start < timeout:
                if stop_event and stop_event.is_set():
                    return ""
                try:
                    resp = session.get(
                        f"{self.api_base}/api/mails?limit=10&offset=0",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json",
                        },
                        timeout=30,
                        verify=False,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, dict):
                            messages = data.get("results") or []
                        elif isinstance(data, list):
                            messages = data
                        else:
                            messages = []
                        for msg in messages:
                            if not isinstance(msg, dict):
                                continue
                            if not self._message_matches_email(msg, email):
                                continue
                            msg_id = msg.get("id")
                            if not msg_id or msg_id in seen_ids:
                                continue
                            seen_ids.add(msg_id)
                            content = msg.get("text") or msg.get("html") or ""
                            if not content and msg.get("raw"):
                                content = parse_raw_email_content(str(msg.get("raw") or ""))
                            code = extract_code(content)
                            if code:
                                return code
                except Exception as exc:
                    logger.warning("Cloudflare 轮询验证码失败: %s", exc)
                time.sleep(3)
        return ""
