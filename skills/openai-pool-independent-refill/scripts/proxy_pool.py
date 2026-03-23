from __future__ import annotations

DEFAULT_PROXY_POOL_URL = "https://zenproxy.top/api/fetch"
DEFAULT_PROXY_POOL_AUTH_MODE = "query"
DEFAULT_PROXY_POOL_API_KEY = "19c0ec43-8f76-4c97-81bc-bcda059eeba4"
DEFAULT_PROXY_POOL_COUNT = 1
DEFAULT_PROXY_POOL_COUNTRY = "US"
POOL_PROXY_FETCH_RETRIES = 3


def normalize_proxy_value(proxy_value) -> str:
    if proxy_value is None:
        return ""
    text = str(proxy_value).strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"http://{text}"
    return text


def to_proxies_dict(proxy_value: str):
    proxy = normalize_proxy_value(proxy_value)
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def build_proxy_pool_config(pool_cfg_raw: dict | None) -> dict:
    raw = pool_cfg_raw or {}
    cfg = {
        "enabled": bool(raw.get("enabled", False)),
        "api_url": str(raw.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL,
        "auth_mode": str(raw.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower() or DEFAULT_PROXY_POOL_AUTH_MODE,
        "api_key": str(raw.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY,
        "count": raw.get("count", DEFAULT_PROXY_POOL_COUNT),
        "country": str(raw.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY,
    }
    if cfg["auth_mode"] not in ("header", "query"):
        cfg["auth_mode"] = DEFAULT_PROXY_POOL_AUTH_MODE
    try:
        cfg["count"] = max(1, min(int(cfg.get("count") or DEFAULT_PROXY_POOL_COUNT), 20))
    except (TypeError, ValueError):
        cfg["count"] = DEFAULT_PROXY_POOL_COUNT
    return cfg
