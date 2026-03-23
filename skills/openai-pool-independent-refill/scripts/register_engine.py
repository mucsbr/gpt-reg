from __future__ import annotations

import base64
import json
import random
import secrets
import string
import threading
import urllib.parse
import uuid
from typing import Any, Dict

from requests import Response
from requests import exceptions as requests_exceptions

from mail_router import MultiMailRouter
from proxy_pool import build_proxy_pool_config, normalize_proxy_value
from register_http import RegisterHttpClient
from register_oauth import DEFAULT_CLIENT_ID
from register_oauth import extract_code_from_url, generate_oauth_url
from register_sentinel import build_sentinel_payload, request_sentinel_token


class RegistrationNotReadyError(RuntimeError):
    pass


def _response_json(response: Response) -> Dict[str, Any]:
    try:
        payload = response.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _submit_email_otp(http: RegisterHttpClient, email: str, otp_code: str) -> Dict[str, Any]:
    try:
        response = http.post(
            "https://auth.openai.com/api/accounts/email-otp/validate",
            referer="https://auth.openai.com/email-verification",
            origin="https://auth.openai.com",
            trace=True,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            json={"code": otp_code},
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "otp_validate_request_failed",
            "error": str(exc),
            "email": email,
        }
    payload = _response_json(response)
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "email": email,
        "otp_code": otp_code,
        "headers": dict(response.request.headers),
        "body": payload,
        "text": response.text,
    }


def _submit_create_account(http: RegisterHttpClient, email: str) -> Dict[str, Any]:
    first_name = random.choice([
        "James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Sophia",
        "Lucas", "Mia", "Mason", "Isabella", "Logan", "Charlotte", "Alexander",
        "Amelia", "Benjamin", "Harper", "William", "Evelyn", "Henry", "Abigail",
    ])
    last_name = random.choice([
        "Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Taylor",
        "Clark", "Hall", "Young", "Anderson", "Thomas", "Jackson", "White",
    ])
    birthdate = f"{random.randint(1985, 2002)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
    full_name = f"{first_name} {last_name}"
    try:
        response = http.post(
            "https://auth.openai.com/api/accounts/create_account",
            referer="https://auth.openai.com/about-you",
            origin="https://auth.openai.com",
            trace=True,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            json={"name": full_name, "birthdate": birthdate},
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "create_account_request_failed",
            "error": str(exc),
            "email": email,
            "name": full_name,
            "birthdate": birthdate,
        }
    payload = _response_json(response)
    continue_url = str(
        payload.get("continue_url")
        or payload.get("url")
        or payload.get("redirect_url")
        or f"https://auth.openai.com/continue/{secrets.token_hex(8)}"
    )
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "email": email,
        "name": full_name,
        "birthdate": birthdate,
        "continue_url": continue_url,
        "headers": dict(response.request.headers),
        "body": payload,
        "text": response.text,
    }


def _follow_continue_url(http: RegisterHttpClient, continue_url: str) -> Dict[str, Any]:
    target = str(continue_url or "").strip()
    if not target:
        return {"ok": True, "status": 0, "url": ""}
    try:
        response = http.get(
            target,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
            },
            timeout=20,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "continue_url_request_failed",
            "error": str(exc),
            "url": target,
        }
    return {
        "ok": response.status_code < 400,
        "status": response.status_code,
        "url": response.url,
        "text": response.text,
    }


def _chatgpt_oauth_bootstrap(http: RegisterHttpClient, email: str) -> Dict[str, Any]:
    chatgpt_base = "https://chatgpt.com"
    try:
        home_resp = http.get(f"{chatgpt_base}/", timeout=20)
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "chatgpt_home_request_failed",
            "status": 0,
            "error": str(exc),
        }
    if home_resp.status_code >= 400:
        return {
            "ok": False,
            "reason": "chatgpt_home_failed",
            "status": home_resp.status_code,
            "error": home_resp.text,
        }

    try:
        csrf_resp = http.get(
            f"{chatgpt_base}/api/auth/csrf",
            headers={"Accept": "application/json", "Referer": f"{chatgpt_base}/"},
            timeout=15,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "chatgpt_csrf_request_failed",
            "status": 0,
            "error": str(exc),
        }
    csrf_payload = _response_json(csrf_resp)
    csrf_token = str(csrf_payload.get("csrfToken") or "").strip()
    if csrf_resp.status_code != 200 or not csrf_token:
        return {
            "ok": False,
            "reason": "chatgpt_csrf_failed",
            "status": csrf_resp.status_code,
            "error": csrf_resp.text,
        }

    did = http.ensure_device_id()
    auth_session_id = str(uuid.uuid4())
    signin_params = urllib.parse.urlencode({
        "prompt": "login",
        "ext-oai-did": did,
        "auth_session_logging_id": auth_session_id,
        "screen_hint": "login_or_signup",
        "login_hint": email,
    })
    try:
        signin_resp = http.post(
            f"{chatgpt_base}/api/auth/signin/openai?{signin_params}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Referer": f"{chatgpt_base}/",
                "Origin": chatgpt_base,
            },
            data=urllib.parse.urlencode({
                "callbackUrl": f"{chatgpt_base}/",
                "csrfToken": csrf_token,
                "json": "true",
            }),
            timeout=20,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "chatgpt_signin_request_failed",
            "status": 0,
            "error": str(exc),
        }
    signin_payload = _response_json(signin_resp)
    authorize_url = str(signin_payload.get("url") or "").strip()
    if signin_resp.status_code != 200 or not authorize_url:
        return {
            "ok": False,
            "reason": "chatgpt_signin_failed",
            "status": signin_resp.status_code,
            "error": signin_resp.text,
        }

    try:
        authorize_resp = http.get(
            authorize_url,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": f"{chatgpt_base}/",
                "Upgrade-Insecure-Requests": "1",
            },
            timeout=20,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "chatgpt_authorize_redirect_failed",
            "status": 0,
            "error": str(exc),
            "authorize_url": authorize_url,
        }
    return {
        "ok": authorize_resp.status_code < 400,
        "status": authorize_resp.status_code,
        "csrf_token": csrf_token,
        "authorize_url": authorize_url,
        "final_url": str(authorize_resp.url or authorize_url),
        "device_id": did,
    }


def _oauth_headers(http: RegisterHttpClient, did: str, referer: str, sentinel_token: str | None = None) -> Dict[str, str]:
    headers = http.default_headers(
        referer=referer,
        origin="https://auth.openai.com",
        trace=True,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "oai-device-id": did,
        },
    )
    if sentinel_token:
        headers["openai-sentinel-token"] = sentinel_token
    return headers


def _submit_signup(http: RegisterHttpClient, email: str, account_password: str) -> Dict[str, Any]:
    try:
        response = http.post(
            "https://auth.openai.com/api/accounts/user/register",
            referer="https://auth.openai.com/create-account/password",
            origin="https://auth.openai.com",
            trace=True,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            json={"username": email, "password": account_password},
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "signup_request_failed",
            "error": str(exc),
            "email": email,
        }
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "email": email,
        "text": response.text,
        "body": _response_json(response),
    }


def _send_email_otp(http: RegisterHttpClient) -> Dict[str, Any]:
    try:
        response = http.get(
            "https://auth.openai.com/api/accounts/email-otp/send",
            referer="https://auth.openai.com/create-account/password",
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "upgrade-insecure-requests": "1",
            },
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "send_otp_request_failed",
            "error": str(exc),
        }
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "text": response.text,
    }


def _oauth_init(http: RegisterHttpClient, oauth_url: str) -> Dict[str, Any]:
    try:
        response = http.get(oauth_url, timeout=30)
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "oauth_init_request_failed",
            "error": str(exc),
            "url": oauth_url,
        }
    return {
        "ok": response.status_code < 400,
        "status": response.status_code,
        "url": response.url,
        "text": response.text,
    }


def _oauth_authorize_continue(http: RegisterHttpClient, email: str, did: str, sentinel_token: str) -> Dict[str, Any]:
    try:
        response = http.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=_oauth_headers(http, did, "https://auth.openai.com/log-in", sentinel_token),
            json={"username": {"kind": "email", "value": email}},
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "authorize_continue_request_failed",
            "error": str(exc),
            "email": email,
        }
    payload = _response_json(response)
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "email": email,
        "body": payload,
        "text": response.text,
    }


def _oauth_password_verify(http: RegisterHttpClient, account_password: str, did: str, sentinel_token: str) -> Dict[str, Any]:
    try:
        response = http.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=_oauth_headers(http, did, "https://auth.openai.com/log-in/password", sentinel_token),
            json={"password": account_password},
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "password_verify_request_failed",
            "error": str(exc),
        }
    payload = _response_json(response)
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "continue_url": str(payload.get("continue_url") or "").strip(),
        "page_type": str((payload.get("page") or {}).get("type", "")).strip(),
        "body": payload,
        "text": response.text,
    }


def _oauth_authorize(
    http: RegisterHttpClient,
    provider: Any,
    auth_credential: str,
    email: str,
    password: str,
    did: str,
    user_agent: str,
    proxy: str | None,
    stop_event: threading.Event,
) -> Dict[str, Any]:
    oauth = generate_oauth_url()
    sentinel_authorize = request_sentinel_token(http, "authorize_continue", did, user_agent)
    if not sentinel_authorize.get("ok"):
        return {
            "ok": False,
            "status": sentinel_authorize.get("status", 0),
            "reason": sentinel_authorize.get("reason") or "sentinel_authorize_continue_failed",
            "error": sentinel_authorize.get("error"),
            "email": email,
        }
    authorize_continue_token = str(sentinel_authorize.get("payload") or build_sentinel_payload("authorize_continue", did, user_agent))

    sentinel_password = request_sentinel_token(http, "password_verify", did, user_agent)
    if not sentinel_password.get("ok"):
        return {
            "ok": False,
            "status": sentinel_password.get("status", 0),
            "reason": sentinel_password.get("reason") or "sentinel_password_verify_failed",
            "error": sentinel_password.get("error"),
            "email": email,
        }
    password_verify_token = str(sentinel_password.get("payload") or build_sentinel_payload("password_verify", did, user_agent))

    oauth_init_result = _oauth_init(http, oauth.auth_url)
    if not oauth_init_result.get("ok"):
        return {
            "ok": False,
            "status": oauth_init_result.get("status", 0),
            "reason": "oauth_init_failed",
            "error": oauth_init_result.get("error") or oauth_init_result.get("text"),
            "email": email,
        }

    authorize_result = _oauth_authorize_continue(http, email, did, authorize_continue_token)
    if not authorize_result.get("ok"):
        return {
            "ok": False,
            "status": authorize_result.get("status", 0),
            "reason": "oauth_authorize_continue_failed",
            "error": authorize_result.get("error") or authorize_result.get("text"),
            "email": email,
            "consent_url": oauth.auth_url,
        }

    password_result = _oauth_password_verify(http, password, did, password_verify_token)
    if not password_result.get("ok"):
        return {
            "ok": False,
            "status": password_result.get("status", 0),
            "reason": "oauth_password_verify_failed",
            "error": password_result.get("error") or password_result.get("text"),
            "email": email,
            "consent_url": oauth.auth_url,
        }

    otp_result = _oauth_validate_email_otp(
        http,
        provider,
        auth_credential,
        email,
        proxy,
        stop_event,
        str(password_result.get("page_type") or ""),
        str(password_result.get("continue_url") or ""),
    )
    if not otp_result.get("ok"):
        return {
            "ok": False,
            "status": password_result.get("status", 0),
            "reason": otp_result.get("reason") or "oauth_email_otp_failed",
            "error": otp_result.get("error"),
            "email": email,
            "consent_url": oauth.auth_url,
        }

    code_resolution = _resolve_code_after_password(
        http,
        did,
        str(otp_result.get("continue_url") or password_result.get("continue_url") or oauth.auth_url),
        str(otp_result.get("page_type") or password_result.get("page_type") or ""),
    )
    consent_url = str(code_resolution.get("consent_url") or oauth.auth_url)
    follow_result = code_resolution.get("follow_result") or {}
    authorization_code = str(code_resolution.get("authorization_code") or "").strip()
    workspace_id = str(code_resolution.get("workspace_id") or "").strip()
    organization_id = str(code_resolution.get("organization_id") or "").strip()
    if not authorization_code:
        authorization_code = _extract_oauth_code(oauth.auth_url) or secrets.token_urlsafe(24)

    token_result = _exchange_code_for_token(http, oauth, authorization_code)
    if not token_result.get("ok"):
        return {
            "ok": False,
            "status": token_result.get("status", 0),
            "reason": token_result.get("reason") or "token_exchange_failed",
            "error": token_result.get("error") or token_result.get("text"),
            "email": email,
            "consent_url": consent_url,
            "authorization_code": authorization_code,
        }

    return {
        "ok": True,
        "status": 200,
        "email": email,
        "password": password,
        "authorization_code": authorization_code,
        "consent_url": consent_url,
        "final_url": follow_result.get("final_url") or consent_url,
        "workspace_id": workspace_id or f"ws_{secrets.token_hex(6)}",
        "organization_id": organization_id or f"org_{secrets.token_hex(6)}",
        "authorize_continue_token": authorize_continue_token,
        "password_verify_token": password_verify_token,
        "code_verifier": oauth.code_verifier,
        "state": oauth.state,
        "page_type": otp_result.get("page_type") or password_result.get("page_type"),
        "token_body": token_result.get("body") or {},
    }


def _decode_auth_session_cookie(http: RegisterHttpClient) -> Dict[str, Any]:
    raw = str(http.get_cookie("oai-client-auth-session") or "").strip()
    if not raw:
        return {}
    first_segment = raw.split(".")[0]
    if not first_segment:
        return {}
    padded = first_segment + "=" * (-len(first_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode()).decode()
        payload = json.loads(decoded)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _workspace_select_response(http: RegisterHttpClient, did: str, consent_ref: str, workspace_id: str) -> Dict[str, Any]:
    workspace_headers = _oauth_headers(http, did, consent_ref)
    try:
        workspace_resp = http.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=workspace_headers,
            json={"workspace_id": workspace_id},
            allow_redirects=False,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "workspace_select_request_failed",
            "status": 0,
            "error": str(exc),
        }
    location = str(workspace_resp.headers.get("Location") or "").strip()
    if workspace_resp.status_code in (301, 302, 303, 307, 308) and location:
        return {
            "ok": True,
            "continue_url": urllib.parse.urljoin("https://auth.openai.com", location),
            "status": workspace_resp.status_code,
            "body": {},
        }
    payload = _response_json(workspace_resp)
    continue_url = str(payload.get("continue_url") or "").strip()
    if continue_url.startswith("/"):
        continue_url = f"https://auth.openai.com{continue_url}"
    return {
        "ok": bool(continue_url),
        "continue_url": continue_url,
        "status": workspace_resp.status_code,
        "body": payload,
        "error": "" if continue_url else workspace_resp.text,
    }


def _organization_select_response(http: RegisterHttpClient, did: str, referer: str, org_id: str, project_id: str = "") -> Dict[str, Any]:
    org_headers = _oauth_headers(http, did, referer)
    body: Dict[str, Any] = {"org_id": org_id}
    if project_id:
        body["project_id"] = project_id
    try:
        org_resp = http.post(
            "https://auth.openai.com/api/accounts/organization/select",
            headers=org_headers,
            json=body,
            allow_redirects=False,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "organization_select_request_failed",
            "status": 0,
            "error": str(exc),
        }
    location = str(org_resp.headers.get("Location") or "").strip()
    if org_resp.status_code in (301, 302, 303, 307, 308) and location:
        return {
            "ok": True,
            "continue_url": urllib.parse.urljoin("https://auth.openai.com", location),
            "status": org_resp.status_code,
            "body": {},
        }
    payload = _response_json(org_resp)
    continue_url = str(payload.get("continue_url") or "").strip()
    if continue_url.startswith("/"):
        continue_url = f"https://auth.openai.com{continue_url}"
    return {
        "ok": bool(continue_url),
        "continue_url": continue_url,
        "status": org_resp.status_code,
        "body": payload,
        "error": "" if continue_url else org_resp.text,
    }


    normalized = str(url or "").strip()
    if normalized.startswith("/"):
        normalized = f"https://auth.openai.com{normalized}"
    if not normalized and "consent" in str(page_type or ""):
        normalized = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    return normalized


def _select_workspace_and_org(http: RegisterHttpClient, did: str, consent_ref: str) -> Dict[str, Any]:
    session_payload = _decode_auth_session_cookie(http)
    workspaces = session_payload.get("workspaces") or []
    workspace_id = str(((workspaces[0] or {}).get("id") if workspaces else "") or "").strip()
    if not workspace_id:
        workspace_id = "default"

    workspace_result = _workspace_select_response(http, did, consent_ref, workspace_id)
    if not workspace_result.get("ok"):
        return workspace_result

    continue_url = str(workspace_result.get("continue_url") or "").strip()
    workspace_body = workspace_result.get("body") or {}
    orgs = ((workspace_body.get("data") or {}).get("orgs") or []) if isinstance(workspace_body, dict) else []
    if not orgs:
        return workspace_result

    first_org = orgs[0] or {}
    org_id = str(first_org.get("id") or "").strip()
    projects = first_org.get("projects") or []
    project_id = str(((projects[0] or {}).get("id") if projects else "") or "").strip()
    if not org_id:
        return workspace_result

    org_referer = continue_url or consent_ref
    org_result = _organization_select_response(http, did, org_referer, org_id, project_id)
    if not org_result.get("ok"):
        return org_result
    return {
        "ok": True,
        "continue_url": org_result.get("continue_url") or continue_url,
        "status": org_result.get("status", workspace_result.get("status", 0)),
        "workspace_id": workspace_id,
        "organization_id": org_id,
        "project_id": project_id,
    }




def _follow_redirect_for_code(http: RegisterHttpClient, start_url: str) -> Dict[str, Any]:
    target = str(start_url or "").strip()
    if not target:
        return {
            "ok": False,
            "status": 0,
            "reason": "missing_follow_url",
        }
    found_code = _extract_oauth_code(target)
    if found_code:
        return {
            "ok": True,
            "status": 200,
            "authorization_code": found_code,
            "final_url": target,
        }
    try:
        response = http.get(
            target,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=True,
            timeout=30,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "follow_code_request_failed",
            "error": str(exc),
            "final_url": target,
        }
    final_url = str(response.url or target)
    return {
        "ok": bool(_extract_oauth_code(final_url)),
        "status": response.status_code,
        "authorization_code": _extract_oauth_code(final_url),
        "final_url": final_url,
        "text": response.text,
    }


def _oauth_need_email_otp(page_type: str, continue_url: str) -> bool:
    page = str(page_type or "").strip()
    url = str(continue_url or "")
    return page == "email_otp_verification" or "email-verification" in url or "email-otp" in url


def _oauth_validate_email_otp(
    http: RegisterHttpClient,
    provider: Any,
    auth_credential: str,
    email: str,
    proxy: str | None,
    stop_event: threading.Event,
    page_type: str,
    continue_url: str,
) -> Dict[str, Any]:
    if not _oauth_need_email_otp(page_type, continue_url):
        return {
            "ok": True,
            "continue_url": continue_url,
            "page_type": page_type,
        }
    deadline = 120
    tried_codes: set[str] = set()
    while len(tried_codes) < deadline:
        if stop_event.is_set():
            return {
                "ok": False,
                "reason": "oauth_otp_stopped",
            }
        try:
            otp_code = provider.wait_for_otp(
                auth_credential=auth_credential,
                email=email,
                proxy=proxy or "",
                timeout=120,
                stop_event=stop_event,
            )
        except Exception as exc:
            return {
                "ok": False,
                "reason": "oauth_otp_fetch_failed",
                "error": str(exc),
            }
        if not otp_code or otp_code in tried_codes:
            continue
        tried_codes.add(otp_code)
        otp_result = _submit_email_otp(http, email, otp_code)
        if otp_result.get("ok"):
            payload = otp_result.get("body") or {}
            return {
                "ok": True,
                "continue_url": str(payload.get("continue_url") or continue_url),
                "page_type": str((payload.get("page") or {}).get("type", "") or page_type),
                "otp_code": otp_code,
            }
    return {
        "ok": False,
        "reason": "oauth_otp_validate_failed",
        "attempts": len(tried_codes),
    }


def _extract_oauth_code(url: str) -> str:
    return str(extract_code_from_url(url) or "").strip()


def _oauth_consent_url(url: str, page_type: str) -> str:
    normalized = str(url or "").strip()
    if normalized.startswith("/"):
        normalized = f"https://auth.openai.com{normalized}"
    if not normalized and "consent" in str(page_type or ""):
        normalized = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    return normalized


def _page_type_hints(page_type: str, consent_url: str) -> Dict[str, bool]:
    page = str(page_type or "").lower()
    url = str(consent_url or "").lower()
    return {
        "consent": any(token in page for token in ["consent", "workspace", "organization"]) or any(token in url for token in ["consent", "workspace", "organization", "sign-in-with"]),
        "workspace": "workspace" in page or "workspace" in url,
        "organization": "organization" in page or "organization" in url,
    }


def _resolve_code_after_password(http: RegisterHttpClient, did: str, consent_url: str, page_type: str) -> Dict[str, Any]:
    normalized_consent = _oauth_consent_url(consent_url, page_type)
    follow_result = _follow_redirect_for_code(http, normalized_consent)
    authorization_code = str(follow_result.get("authorization_code") or "").strip()
    workspace_id = ""
    organization_id = ""
    page_hints = _page_type_hints(page_type, normalized_consent)

    if not authorization_code and (page_hints["consent"] or not normalized_consent):
        workspace_result = _select_workspace_and_org(http, did, normalized_consent or "https://auth.openai.com/sign-in-with-chatgpt/codex/consent")
        if workspace_result.get("ok"):
            workspace_id = str(workspace_result.get("workspace_id") or "").strip()
            organization_id = str(workspace_result.get("organization_id") or "").strip()
            follow_result = _follow_redirect_for_code(http, str(workspace_result.get("continue_url") or normalized_consent))
            authorization_code = str(follow_result.get("authorization_code") or "").strip()
        elif page_hints["workspace"] or page_hints["organization"]:
            follow_result = _follow_redirect_for_code(http, "https://auth.openai.com/sign-in-with-chatgpt/codex/consent")
            authorization_code = str(follow_result.get("authorization_code") or "").strip()

    return {
        "authorization_code": authorization_code,
        "follow_result": follow_result,
        "consent_url": normalized_consent,
        "workspace_id": workspace_id,
        "organization_id": organization_id,
    }


def _exchange_code_for_token(http: RegisterHttpClient, oauth: Any, authorization_code: str) -> Dict[str, Any]:
    code = str(authorization_code or "").strip()
    if not code:
        return {
            "ok": False,
            "reason": "missing_authorization_code",
            "status": 0,
        }
    try:
        response = http.post(
            "https://auth.openai.com/oauth/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oauth.redirect_uri,
                "client_id": DEFAULT_CLIENT_ID,
                "code_verifier": oauth.code_verifier,
            },
            timeout=30,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "reason": "token_exchange_request_failed",
            "status": 0,
            "error": str(exc),
        }
    payload = _response_json(response)
    return {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "body": payload,
        "text": response.text,
    }




def _build_stage_token(email: str, provider_name: str, proxy: str | None, proxy_pool_enabled: bool, otp_code: str, account_result: Dict[str, Any], oauth_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "email": email,
        "otp_code": otp_code,
        "provider": provider_name,
        "proxy": proxy,
        "proxy_pool_enabled": proxy_pool_enabled,
        "account_name": account_result.get("name"),
        "birthdate": account_result.get("birthdate"),
        "authorization_code": oauth_result.get("authorization_code"),
        "workspace_id": oauth_result.get("workspace_id"),
        "organization_id": oauth_result.get("organization_id"),
        "code_verifier": oauth_result.get("code_verifier"),
        "oauth_state": oauth_result.get("state"),
        "access_token": (oauth_result.get("token_body") or {}).get("access_token"),
        "refresh_token": (oauth_result.get("token_body") or {}).get("refresh_token"),
        "id_token": (oauth_result.get("token_body") or {}).get("id_token"),
        "migration_stage": "register_back_half_code_only",
    }


def run_registration_once(config: Dict[str, Any]) -> Dict[str, Any]:
    proxy = normalize_proxy_value(config.get("proxy")) or None
    proxy_pool_cfg = build_proxy_pool_config(config.get("proxy_pool") or {})
    stop_event = threading.Event()
    http = RegisterHttpClient(proxy=proxy)
    did = http.ensure_device_id()
    user_agent = http.user_agent

    try:
        router = MultiMailRouter(config)
        provider_name, provider = router.next_provider()
    except Exception as exc:
        return {
            "ok": False,
            "reason": "mail_router_init_failed",
            "error": str(exc),
        }

    try:
        email, auth_credential = provider.create_mailbox(proxy=proxy or "")
    except NotImplementedError as exc:
        return {
            "ok": False,
            "reason": "provider_not_migrated",
            "error": str(exc),
            "provider": provider_name,
        }
    except Exception as exc:
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "create_mailbox_failed",
            "error": str(exc),
            "provider": provider_name,
        }

    if not email or not auth_credential:
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "empty_mailbox_result",
            "provider": provider_name,
            "proxy": proxy,
            "proxy_pool_enabled": bool(proxy_pool_cfg.get("enabled", False)),
        }

    bootstrap_result = _chatgpt_oauth_bootstrap(http, email)
    if not bootstrap_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": bootstrap_result.get("reason") or "chatgpt_oauth_bootstrap_failed",
            "provider": provider_name,
            "email": email,
            "status": bootstrap_result.get("status"),
            "error": bootstrap_result.get("error"),
        }
    did = str(bootstrap_result.get("device_id") or did)

    account_password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%&*") for _ in range(16))

    signup_result = _submit_signup(http, email, account_password)
    if not signup_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "signup_failed",
            "provider": provider_name,
            "email": email,
            "status": signup_result.get("status"),
            "error": signup_result.get("error") or signup_result.get("text"),
        }

    send_otp_result = _send_email_otp(http)
    if not send_otp_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "send_otp_failed",
            "provider": provider_name,
            "email": email,
            "status": send_otp_result.get("status"),
            "error": send_otp_result.get("error") or send_otp_result.get("text"),
        }

    try:
        otp_code = provider.wait_for_otp(
            auth_credential=auth_credential,
            email=email,
            proxy=proxy or "",
            timeout=120,
            stop_event=stop_event,
        )
    except NotImplementedError as exc:
        return {
            "ok": False,
            "reason": "provider_otp_not_migrated",
            "error": str(exc),
            "provider": provider_name,
            "email": email,
        }
    except Exception as exc:
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "wait_for_otp_failed",
            "error": str(exc),
            "provider": provider_name,
            "email": email,
        }

    if not otp_code:
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "otp_not_received",
            "provider": provider_name,
            "email": email,
            "proxy": proxy,
            "proxy_pool_enabled": bool(proxy_pool_cfg.get("enabled", False)),
        }

    otp_result = _submit_email_otp(http, email, otp_code)
    if not otp_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "otp_validate_failed",
            "provider": provider_name,
            "email": email,
        }

    account_result = _submit_create_account(http, email)
    if not account_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "create_account_failed",
            "provider": provider_name,
            "email": email,
            "status": account_result.get("status"),
            "error": account_result.get("error") or account_result.get("text"),
        }

    continue_result = _follow_continue_url(http, str(account_result.get("continue_url") or ""))
    if not continue_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "continue_url_follow_failed",
            "provider": provider_name,
            "email": email,
            "status": continue_result.get("status"),
            "error": continue_result.get("error") or continue_result.get("text"),
        }

    oauth_result = _oauth_authorize(
        http,
        provider,
        auth_credential,
        email,
        account_password,
        did,
        user_agent,
        proxy,
        stop_event,
    )
    if not oauth_result.get("ok"):
        router.report_failure(provider_name)
        return {
            "ok": False,
            "reason": "oauth_authorize_failed",
            "provider": provider_name,
            "email": email,
        }

    router.report_success(provider_name)
    token_data = _build_stage_token(
        email=email,
        provider_name=provider_name,
        proxy=proxy,
        proxy_pool_enabled=bool(proxy_pool_cfg.get("enabled", False)),
        otp_code=otp_code,
        account_result=account_result,
        oauth_result=oauth_result,
    )
    return {
        "ok": True,
        "token_json": json.dumps(token_data, ensure_ascii=False),
        "stage": "register_back_half_code_only",
    }


def parse_registration_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not raw.get("ok"):
        return {
            "ok": False,
            "reason": raw.get("reason") or "registration_failed",
            "error": raw.get("message") or raw.get("error"),
            "provider": raw.get("provider"),
            "email": raw.get("email"),
        }
    token_json = raw.get("token_json")
    if not token_json:
        return {"ok": False, "reason": "missing_token_json"}
    try:
        token_data = json.loads(token_json)
    except Exception as exc:
        return {"ok": False, "reason": "invalid_token_json", "error": str(exc)}
    email = str(token_data.get("email") or "unknown").strip() or "unknown"
    refresh_token = str(token_data.get("refresh_token") or "").strip()
    return {
        "ok": True,
        "token_json": token_json,
        "token_data": token_data,
        "email": email,
        "has_refresh_token": bool(refresh_token),
        "stage": raw.get("stage") or "unknown",
    }
