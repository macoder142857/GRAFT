"""HTTP request views and rule matching primitives."""

from __future__ import annotations

import html
import json
import posixpath
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit


def _normalize_attack_surface(value: str) -> str:
    text = str(value or "")
    for _ in range(3):
        decoded = html.unescape(unquote_plus(text))
        if decoded == text:
            break
        text = decoded
    text = text.replace("\x00", "")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    return re.sub(r"\s+", " ", text).strip().lower()


def _normalize_path_surface(value: str) -> str:
    decoded = _normalize_attack_surface(value).replace("\\", "/")
    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    return normalized if normalized != "/." else "/"


def _apply_transforms(text: str, transforms: list[str]) -> str:
    value = text
    for transform in transforms:
        key = str(transform).strip().lower()
        if key == "lowercase":
            value = value.lower()
        elif key in {"html_entity_decode", "htmlentitydecode"}:
            value = html.unescape(value)
        elif key in {"url_decode", "urldecode", "urldecodeuni", "t:urldecodeuni"}:
            value = unquote_plus(value)
        elif key in {"remove_nulls", "strip_nulls"}:
            value = value.replace("\x00", "").replace("%00", "")
        elif key == "remove_comments":
            value = re.sub(r"/\*.*?\*/", "", value, flags=re.DOTALL)
            value = re.sub(r"<!--.*?-->", "", value, flags=re.DOTALL)
        elif key == "normalize_path":
            value = _normalize_path_surface(value)
        elif key in {"compress_whitespace", "normalize_whitespace", "normalize_space"}:
            value = re.sub(r"\s+", " ", value).strip()
        elif key == "recursive_decode":
            for _ in range(3):
                decoded = unquote_plus(value)
                if decoded == value:
                    break
                value = decoded
    return value


def _extract_request_parts(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    req_data = row.get("req_data") if isinstance(row.get("req_data"), dict) else {}
    request = row.get("request") if isinstance(row.get("request"), dict) else {}
    query = str(req_data.get("query") or request.get("query") or "")
    body = str(req_data.get("body") or request.get("body") or "")
    headers_obj = req_data.get("headers") or request.get("headers") or {}
    headers = dict(headers_obj) if isinstance(headers_obj, dict) else {}
    target = str(
        row.get("request_target")
        or row.get("url")
        or request.get("url")
        or ""
    ).strip()
    path = ""
    if target:
        parsed = urlsplit(target)
        path = parsed.path or target.split("?", 1)[0]
        query = query or parsed.query

    raw = str(row.get("raw_log") or "")
    if raw:
        head, _, raw_body = raw.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        if lines:
            match = re.match(
                r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+?)\s+HTTP/\d(?:\.\d)?$",
                lines[0].strip(),
                flags=re.IGNORECASE,
            )
            if match and not path:
                parsed = urlsplit(match.group(1))
                path = parsed.path or match.group(1).split("?", 1)[0]
                query = query or parsed.query
            for line in lines[1:]:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                headers.setdefault(key.strip(), value.strip())
        body = body or raw_body

    if not path and query.startswith("/"):
        parsed = urlsplit(query)
        path, query = parsed.path, parsed.query
    headers_text = "\n".join(
        f"{str(key).lower()}:{value}" for key, value in headers.items()
    )
    cookie = next(
        (str(value) for key, value in headers.items() if str(key).lower() == "cookie"),
        "",
    )
    return path, query, body, headers_text, cookie


def _body_views(body: str) -> dict[str, str]:
    views: dict[str, str] = {}
    pairs = parse_qsl(body, keep_blank_values=True)
    if pairs:
        keys = [_normalize_attack_surface(key) for key, _ in pairs]
        values = [_normalize_attack_surface(value) for _, value in pairs]
        views["body_keys_norm"] = " ".join(dict.fromkeys(filter(None, keys)))
        views["body_values_norm"] = " ".join(dict.fromkeys(filter(None, values)))[:8192]
        views["body_pairs_norm"] = " ".join(
            dict.fromkeys(
                _normalize_attack_surface(f"{key}={value}") for key, value in pairs
            )
        )[:8192]
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return views
    keys: list[str] = []
    values: list[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                keys.append(str(key))
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif item is not None:
            values.append(str(item))

    walk(parsed)
    if keys:
        views["body_keys_norm"] = _normalize_attack_surface(" ".join(keys))[:4096]
    if values:
        views["body_values_norm"] = _normalize_attack_surface(" ".join(values))[:8192]
    return views


def _build_waf_views(row: dict[str, Any]) -> dict[str, str]:
    path, query, body, headers, cookie = _extract_request_parts(row)
    target = f"{path}?{query}" if query else path
    views = {
        "url": _normalize_attack_surface(path),
        "url_raw_norm": path.lower(),
        "path_norm": _normalize_path_surface(path),
        "request_target_norm": _normalize_attack_surface(target),
        "request_target_raw_norm": target.lower(),
        "query_norm": _normalize_attack_surface(query)[:2048],
        "body_norm": _normalize_attack_surface(body)[:8192],
        "body_values_norm": _normalize_attack_surface(body)[:8192],
        "headers_norm": _normalize_attack_surface(headers)[:4096],
        "cookie_norm": _normalize_attack_surface(cookie)[:4096],
    }
    anomalies: list[str] = []
    lower_headers = headers.lower()
    if lower_headers.count("content-length:") > 1:
        anomalies.append("duplicate_content_length")
    if "content-length:" in lower_headers and "transfer-encoding:" in lower_headers:
        anomalies.append("cl_te_conflict")
    if "%0d" in query.lower() or "%0a" in query.lower():
        anomalies.append("crlf_in_query")
    if "%00" in query.lower() or "%00" in body.lower():
        anomalies.append("encoded_nul")
    if _normalize_path_surface(path) != _normalize_attack_surface(path):
        anomalies.append("path_canonicalization_delta")
    if anomalies:
        views["protocol_anomalies_norm"] = " ".join(dict.fromkeys(anomalies))
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        keys = [_normalize_attack_surface(key) for key, _ in pairs]
        values = [_normalize_attack_surface(value) for _, value in pairs]
        views["query_keys_norm"] = " ".join(dict.fromkeys(filter(None, keys)))
        views["query_key_paths_norm"] = views["query_keys_norm"]
        views["query_values_norm"] = " ".join(dict.fromkeys(filter(None, values)))[:4096]
        views["query_pairs_norm"] = " ".join(
            dict.fromkeys(
                _normalize_attack_surface(f"{key}={value}") for key, value in pairs
            )
        )[:4096]
        counts: dict[str, int] = {}
        repeated: list[str] = []
        for key in keys:
            counts[key] = counts.get(key, 0) + 1
            if counts[key] > 1 and key not in repeated:
                repeated.append(key)
        if repeated:
            views["query_repeated_keys_norm"] = " ".join(repeated)
    if body:
        views.update(_body_views(body))
    return views


def _compile_rules_from_items(
    items: Iterable[dict[str, Any]],
    source_type: str,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    del source_type
    compiled: list[dict[str, Any]] = []
    stats = {"entries_total": 0, "compiled_ok": 0, "compile_error": 0}
    for item in items:
        if not isinstance(item, dict) or not item.get("enabled", True):
            continue
        stats["entries_total"] += 1
        prefilter = str(item.get("prefilter_pattern") or "").strip()
        detection = str(
            item.get("detection_pattern") or item.get("regex") or ""
        ).strip()
        keywords = [
            str(value).lower()
            for value in item.get("ac_keywords") or []
            if str(value).strip()
        ]
        if not prefilter and not detection and not keywords:
            continue
        try:
            prefilter_re = re.compile(prefilter, re.IGNORECASE) if prefilter else None
            detection_re = re.compile(detection, re.IGNORECASE) if detection else None
        except re.error:
            stats["compile_error"] += 1
            continue
        compiled.append(
            {
                "rule_id": str(item.get("rule_id") or "unknown"),
                "prefilter_re": prefilter_re,
                "detection_re": detection_re,
                "transforms": list(
                    item.get("transforms") or item.get("transform_chain") or []
                ),
                "action": str(item.get("action") or "block").lower(),
                "description": str(item.get("description") or ""),
                "zones": list(item.get("match_zone") or [])
                or ([str(item["field"])] if item.get("field") else []),
                "keywords": list(dict.fromkeys(keywords)),
                "index_keywords": list(dict.fromkeys(keywords)),
                "source_file": str(item.get("source_file") or ""),
            }
        )
        stats["compiled_ok"] += 1
    return compiled, stats


def _build_global_keyword_index(rules: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "keyword_to_rules": {
            keyword: {
                index
                for index, rule in enumerate(rules)
                if keyword in (rule.get("index_keywords") or [])
            }
            for keyword in {
                keyword
                for rule in rules
                for keyword in rule.get("index_keywords") or []
            }
        }
    }


def _default_match_zones() -> list[str]:
    return [
        "request_target_norm",
        "path_norm",
        "query_norm",
        "query_values_norm",
        "query_pairs_norm",
        "query_keys_norm",
        "body_norm",
        "body_values_norm",
        "body_pairs_norm",
        "body_keys_norm",
        "protocol_anomalies_norm",
        "url",
        "headers_norm",
        "cookie_norm",
    ]


def _match_rule_on_views(rule: dict[str, Any], views: dict[str, str]) -> bool:
    zones = rule.get("zones") or _default_match_zones()
    keywords = [
        str(keyword).lower()
        for keyword in rule.get("keywords") or []
        if str(keyword).strip()
    ]
    for zone in zones:
        value = str(views.get(str(zone)) or "")
        if not value:
            continue
        transformed = _apply_transforms(
            value,
            [str(item) for item in rule.get("transforms") or []],
        )
        if keywords and not any(keyword in transformed.lower() for keyword in keywords):
            continue
        if rule.get("prefilter_re") and not rule["prefilter_re"].search(transformed):
            continue
        if rule.get("detection_re") and not rule["detection_re"].search(transformed):
            continue
        return True
    return False
