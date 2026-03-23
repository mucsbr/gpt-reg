from __future__ import annotations

import itertools
import random
import threading
from typing import Any, Dict, List, Tuple

from mail_providers import (
    CloudflareTempEmailProvider,
    DuckMailProvider,
    MailProvider,
    MailTmProvider,
    MoeMailProvider,
)


def create_provider_by_name(provider_type: str, mail_cfg: Dict[str, Any]) -> MailProvider:
    provider_type = provider_type.lower().strip()
    api_base = str(mail_cfg.get("api_base", "")).strip()
    if provider_type == "moemail":
        return MoeMailProvider(
            api_base=api_base or "https://your-moemail-api.example.com",
            api_key=str(mail_cfg.get("api_key", "")).strip(),
        )
    if provider_type == "duckmail":
        return DuckMailProvider(
            api_base=api_base or "https://api.duckmail.sbs",
            bearer_token=str(mail_cfg.get("bearer_token", "")).strip(),
        )
    if provider_type == "cloudflare_temp_email":
        return CloudflareTempEmailProvider(
            api_base=api_base,
            admin_password=str(mail_cfg.get("admin_password", "")).strip(),
            domain=str(mail_cfg.get("domain", "")).strip(),
        )
    if provider_type == "mailtm":
        return MailTmProvider(api_base=api_base or "https://api.mail.tm")
    raise ValueError(f"未知邮箱提供商: {provider_type}")


class MultiMailRouter:
    def __init__(self, config: Dict[str, Any]):
        providers_list: List[str] = config.get("mail_providers") or []
        provider_configs: Dict[str, Dict[str, Any]] = config.get("mail_provider_configs") or {}
        self.strategy: str = config.get("mail_strategy", "round_robin")
        if not providers_list:
            legacy = config.get("mail_provider", "mailtm")
            providers_list = [legacy]
            provider_configs = {legacy: config.get("mail_config") or {}}
        self._provider_names: List[str] = []
        self._providers: Dict[str, MailProvider] = {}
        self._failures: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._counter = itertools.count()
        for name in providers_list:
            provider = create_provider_by_name(name, provider_configs.get(name, {}))
            self._provider_names.append(name)
            self._providers[name] = provider
            self._failures[name] = 0
        if not self._providers:
            fallback = create_provider_by_name("mailtm", {})
            self._provider_names = ["mailtm"]
            self._providers = {"mailtm": fallback}
            self._failures = {"mailtm": 0}

    def next_provider(self) -> Tuple[str, MailProvider]:
        with self._lock:
            names = self._provider_names
            if not names:
                raise RuntimeError("无可用邮箱提供商")
            if self.strategy == "random":
                name = random.choice(names)
            elif self.strategy == "failover":
                name = min(names, key=lambda item: self._failures.get(item, 0))
            else:
                idx = next(self._counter) % len(names)
                name = names[idx]
            return name, self._providers[name]

    def report_success(self, provider_name: str) -> None:
        with self._lock:
            self._failures[provider_name] = max(0, self._failures.get(provider_name, 0) - 1)

    def report_failure(self, provider_name: str) -> None:
        with self._lock:
            self._failures[provider_name] = self._failures.get(provider_name, 0) + 1
