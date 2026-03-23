#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_literal(text: str, pattern: str, default=None, cast=None):
    m = re.search(pattern, text, re.MULTILINE)
    if not m:
        return default
    raw = m.group(1)
    if cast is None:
        return raw
    try:
        return cast(raw)
    except Exception:
        return default


def _extract_defaults(server_text: str) -> dict:
    defaults = {}
    defaults["min_candidates"] = _extract_literal(
        server_text,
        r'"min_candidates"\s*:\s*(\d+)',
        default=None,
        cast=int,
    )
    defaults["sub2api_min_candidates"] = _extract_literal(
        server_text,
        r'"sub2api_min_candidates"\s*:\s*(\d+)',
        default=None,
        cast=int,
    )
    defaults["upload_mode"] = _extract_literal(
        server_text,
        r'"upload_mode"\s*:\s*"([^"]+)"',
        default=None,
    )
    return defaults


def _load_runtime_config(project_root: Path) -> tuple[dict, str]:
    data_cfg = project_root / "data" / "sync_config.json"
    cli_cfg = project_root / "config" / "sync_config.json"

    if data_cfg.exists():
        try:
            return json.loads(_read_text(data_cfg)), str(data_cfg)
        except Exception as e:
            return {"_load_error": str(e)}, str(data_cfg)

    if cli_cfg.exists():
        try:
            return json.loads(_read_text(cli_cfg)), str(cli_cfg)
        except Exception as e:
            return {"_load_error": str(e)}, str(cli_cfg)

    return {}, ""


def _bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    return default


def _gap(threshold, current):
    if threshold is None or current is None:
        return None
    try:
        return max(0, int(threshold) - int(current))
    except Exception:
        return None


def _load_pool_snapshot(project_root: Path) -> dict:
    path = project_root / "data" / "refill_snapshot.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(_read_text(path))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _normalize_mode(raw: str) -> str:
    mode = str(raw or "snapshot").strip().lower() or "snapshot"
    return mode if mode in {"snapshot", "decoupled"} else "snapshot"


def build_report(project_root: Path) -> dict:
    server_path = project_root / "openai_pool_orchestrator" / "server.py"
    register_path = project_root / "openai_pool_orchestrator" / "register.py"

    server_text = _read_text(server_path)
    register_text = _read_text(register_path)
    defaults = _extract_defaults(server_text)
    cfg, cfg_path = _load_runtime_config(project_root)
    snapshot = _load_pool_snapshot(project_root)

    auto_register = _bool(cfg.get("auto_register"), False)
    auto_sync = _bool(cfg.get("auto_sync"), True)
    proxy = str(cfg.get("proxy") or "").strip()
    proxy_pool_enabled = _bool(cfg.get("proxy_pool_enabled"), False)
    upload_mode = _normalize_mode(cfg.get("upload_mode") or defaults.get("upload_mode") or "snapshot")

    cpa_threshold = int(cfg.get("min_candidates") or defaults.get("min_candidates") or 800)
    sub2api_threshold = int(cfg.get("sub2api_min_candidates") or defaults.get("sub2api_min_candidates") or 200)

    cpa_current = snapshot.get("cpa_candidates")
    sub2api_current = snapshot.get("sub2api_candidates")
    cpa_gap = _gap(cpa_threshold, cpa_current)
    sub2api_gap = _gap(sub2api_threshold, sub2api_current)

    effective_sub2api_gap = sub2api_gap if auto_sync else 0
    if cpa_gap is None and sub2api_gap is None:
        total_gap = None
    elif upload_mode == "snapshot":
        total_gap = (cpa_gap or 0) + (effective_sub2api_gap or 0)
    else:
        total_gap = max(cpa_gap or 0, effective_sub2api_gap or 0)

    cli_reads_legacy_config = '"config", "sync_config.json"' in register_text
    web_uses_data_config = 'CONFIG_FILE = DATA_DIR / "sync_config.json"' in _read_text(project_root / "openai_pool_orchestrator" / "__init__.py")

    blockers = []
    if not auto_register:
        blockers.append("auto_register 未开启")
    if not proxy and not proxy_pool_enabled:
        blockers.append("未配置固定代理且代理池未启用")
    if total_gap == 0:
        blockers.append("gap 计算结果为 0")
    if total_gap is None:
        blockers.append("缺少池快照，无法本地估算 gap")

    findings = []
    findings.append(f"补号策略: {upload_mode}")
    findings.append(f"auto_register: {'on' if auto_register else 'off'}")
    findings.append(f"auto_sync: {'on' if auto_sync else 'off'}")
    findings.append(f"代理: {'fixed' if proxy else 'none'} / 代理池: {'on' if proxy_pool_enabled else 'off'}")
    findings.append(f"CPA 阈值/当前/gap: {cpa_threshold}/{cpa_current if cpa_current is not None else '?'}/{cpa_gap if cpa_gap is not None else '?'}")
    findings.append(f"Sub2Api 阈值/当前/gap: {sub2api_threshold}/{sub2api_current if sub2api_current is not None else '?'}/{sub2api_gap if sub2api_gap is not None else '?'}")
    findings.append(f"总 gap 估算: {total_gap if total_gap is not None else '?'}")

    if cli_reads_legacy_config and web_uses_data_config:
        findings.append("检测到 Web/CLI 配置路径不一致：Web 使用 data/sync_config.json，CLI 仍读取 config/sync_config.json")

    return {
        "project_root": str(project_root),
        "config_path": cfg_path or None,
        "pool_snapshot_path": str(project_root / "data" / "refill_snapshot.json") if (project_root / "data" / "refill_snapshot.json").exists() else None,
        "effective": {
            "auto_register": auto_register,
            "auto_sync": auto_sync,
            "proxy_configured": bool(proxy),
            "proxy_pool_enabled": proxy_pool_enabled,
            "upload_mode": upload_mode,
            "cpa_threshold": cpa_threshold,
            "sub2api_threshold": sub2api_threshold,
            "cpa_candidates": cpa_current,
            "sub2api_candidates": sub2api_current,
            "cpa_gap": cpa_gap,
            "sub2api_gap": sub2api_gap,
            "total_gap": total_gap,
        },
        "blockers": blockers,
        "findings": findings,
        "notes": [
            "这是静态诊断脚本，不会调用外部平台 API。",
            "如需更准确判断当前池状态，可先手动把实时 candidates 写入 data/refill_snapshot.json。",
            "refill_snapshot.json 示例：{\"cpa_candidates\": 780, \"sub2api_candidates\": 160}",
        ],
    }


def main() -> int:
    if len(sys.argv) > 2:
        print("Usage: refill_diagnose.py [project_root]", file=sys.stderr)
        return 2

    project_root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path.cwd().resolve()
    try:
        report = build_report(project_root)
    except FileNotFoundError as e:
        print(json.dumps({"error": f"missing file: {e}"}, ensure_ascii=False, indent=2))
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
