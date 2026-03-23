from __future__ import annotations

import base64
import json
import random
import time
import uuid
from typing import Any, Dict, Optional

from requests import exceptions as requests_exceptions


class SentinelGen:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, dev_id: str, ua: str):
        self.dev_id = dev_id
        self.ua = ua
        self.req_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        return format(h & 0xFFFFFFFF, "08x")

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()

    def _cfg(self):
        now_s = time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime())
        perf = random.uniform(1000, 50000)
        return [
            "1920x1080", now_s, 4294705152, random.random(), self.ua,
            "https://sentinel.openai.com/sentinel/sdk.js",
            None, None, "en-US", "en-US,en", random.random(),
            "vendorSub-undefined", "location", "Object", perf, self.sid, "", 8, time.time() * 1000 - perf,
        ]

    def gen_req_token(self) -> str:
        cfg = self._cfg()
        cfg[3] = 1
        cfg[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(cfg)

    def gen_token(self, seed: str | None = None, diff: str = "0") -> str:
        seed = seed or self.req_seed
        start_time = time.time()
        cfg = self._cfg()
        for nonce in range(self.MAX_ATTEMPTS):
            cfg[3] = nonce
            cfg[9] = round((time.time() - start_time) * 1000)
            encoded = self._b64(cfg)
            digest = self._fnv1a(seed + encoded)
            if digest[: len(diff)] <= diff:
                return "gAAAAAB" + encoded + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


def build_sentinel_payload(flow: str, did: str, ua: str) -> str:
    sentinel = SentinelGen(did, ua)
    return json.dumps({
        "p": sentinel.gen_req_token(),
        "t": "",
        "c": "stub-token",
        "id": did,
        "flow": flow,
    }, separators=(",", ":"))


def request_sentinel_token(http: Any, flow: str, did: str, ua: str) -> Dict[str, Any]:
    sentinel = SentinelGen(did, ua)
    req_body = json.dumps({"p": sentinel.gen_req_token(), "id": did, "flow": flow})
    try:
        response = http.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Origin": "https://sentinel.openai.com",
                "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            },
            data=req_body,
        )
    except requests_exceptions.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "reason": "sentinel_request_failed",
            "error": str(exc),
        }
    if response.status_code != 200:
        return {
            "ok": False,
            "status": response.status_code,
            "reason": "sentinel_request_rejected",
            "error": response.text,
        }
    try:
        payload = response.json()
    except Exception:
        return {
            "ok": False,
            "status": response.status_code,
            "reason": "sentinel_invalid_response",
            "error": response.text,
        }
    challenge_token = str(payload.get("token") or "").strip()
    if not challenge_token:
        return {
            "ok": False,
            "status": response.status_code,
            "reason": "sentinel_missing_token",
            "error": response.text,
        }
    pow_data = payload.get("proofofwork") or {}
    if pow_data.get("required") and pow_data.get("seed"):
        proof_token = sentinel.gen_token(seed=str(pow_data.get("seed") or ""), diff=str(pow_data.get("difficulty") or "0"))
    else:
        proof_token = sentinel.gen_req_token()
    return {
        "ok": True,
        "status": response.status_code,
        "payload": json.dumps({
            "p": proof_token,
            "t": "",
            "c": challenge_token,
            "id": did,
            "flow": flow,
        }, separators=(",", ":")),
        "challenge": payload,
    }
