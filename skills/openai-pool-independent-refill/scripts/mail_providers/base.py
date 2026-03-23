from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Optional, Tuple
import threading


class MailProvider(ABC):
    @abstractmethod
    def create_mailbox(
        self,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
    ) -> Tuple[str, str]:
        pass

    @abstractmethod
    def wait_for_otp(
        self,
        auth_credential: str,
        email: str,
        proxy: str = "",
        proxy_selector: Optional[Callable[[], str]] = None,
        timeout: int = 120,
        stop_event: Optional[threading.Event] = None,
    ) -> str:
        pass
