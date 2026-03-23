from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class OAuthRequest:
    auth_url: str
    code_verifier: str
    state: str
    redirect_uri: str


DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"
DEFAULT_SCOPE = "openid profile email offline_access"


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _pkce_verifier() -> str:
    return _b64url_no_pad(secrets.token_bytes(64))


def _pkce_challenge(code_verifier: str) -> str:
    return _b64url_no_pad(hashlib.sha256(code_verifier.encode()).digest())


def generate_oauth_url() -> OAuthRequest:
    state = secrets.token_urlsafe(16)
    code_verifier = _pkce_verifier()
    code_challenge = _pkce_challenge(code_verifier)
    query = urllib.parse.urlencode({
        "client_id": DEFAULT_CLIENT_ID,
        "redirect_uri": DEFAULT_REDIRECT_URI,
        "response_type": "code",
        "scope": DEFAULT_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    })
    return OAuthRequest(
        auth_url=f"https://auth.openai.com/authorize?{query}",
        code_verifier=code_verifier,
        state=state,
        redirect_uri=DEFAULT_REDIRECT_URI,
    )


def extract_code_from_url(url: str) -> Optional[str]:
    if not url or "code=" not in url:
        return None
    try:
        return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]
    except Exception:
        return None
