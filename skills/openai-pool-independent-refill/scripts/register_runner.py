from __future__ import annotations

from typing import Any, Dict, List

from register_engine import RegistrationNotReadyError, parse_registration_result, run_registration_once


def run_single_registration(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = run_registration_once(config)
    return parse_registration_result(raw)


def run_registration(config: Dict[str, Any], target_count: int = 1) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    count = max(1, int(target_count))
    for index in range(count):
        item = run_single_registration(config)
        item["attempt"] = index + 1
        results.append(item)
    return results
