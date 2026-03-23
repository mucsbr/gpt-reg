from .base import MailProvider
from .mailtm import MailTmProvider
from .moemail import MoeMailProvider
from .duckmail import DuckMailProvider
from .cloudflare_temp import CloudflareTempEmailProvider

__all__ = [
    "MailProvider",
    "MailTmProvider",
    "MoeMailProvider",
    "DuckMailProvider",
    "CloudflareTempEmailProvider",
]
