"""Contribution graph for GRAFT rule governance."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9_.$:/-]{3,}", re.IGNORECASE)


def build_rule_contribution_graph(
    *,
    baseline_entries: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    accepted: list[dict[str, Any]],
    regression_report: list[dict[str, Any]],
) -> dict[str, Any]:
    accepted_ids = {str(item.get("rule_id")) for item in accepted}
    baseline_nodes = [_node(item, "baseline") for item in baseline_entries]
    candidate_nodes = [_node(item, "candidate") for item in candidates]
    report_by_id = {str(item.get("rule_id")): item for item in regression_report}

    nodes: list[dict[str, Any]] = []
    for node in baseline_nodes:
        nodes.append(_public_node(node, accepted=False, report={}))
    for node in candidate_nodes:
        report = report_by_id.get(node["rule_id"]) or {}
        nodes.append(_public_node(node, accepted=node["rule_id"] in accepted_ids, report=report))

    edges: list[dict[str, Any]] = []
    edges.extend(_duplicate_edges(candidate_nodes))
    edges.extend(_subsumption_edges(baseline_nodes, candidate_nodes))
    edges.extend(_similarity_edges(candidate_nodes))
    edges.extend(_conflict_edges(candidate_nodes, report_by_id))
    edges.extend(_contribution_edges(candidate_nodes, report_by_id))

    return {
        "schema": "graft.rule_contribution_graph.v1",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "summary": _summary(nodes, edges),
        "nodes": nodes,
        "edges": edges,
    }


def write_rule_contribution_graph(path: Path, graph: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _node(rule: dict[str, Any], source: str) -> dict[str, Any]:
    rule_id = str(rule.get("rule_id") or rule.get("id") or "")
    zones = tuple(sorted(str(item).strip().lower() for item in rule.get("match_zone") or [] if str(item).strip()))
    keywords = tuple(sorted(str(item).strip().lower() for item in rule.get("ac_keywords") or [] if str(item).strip()))
    regex = str(rule.get("regex") or rule.get("detection_pattern") or rule.get("prefilter_pattern") or "").lower()
    tokens = tuple(sorted(set(keywords) | _tokens(regex)))
    attack_type = str(rule.get("attack_type") or rule.get("family") or "unknown").strip().lower() or "unknown"
    fp = hashlib.sha256(
        json.dumps(
            {
                "zones": zones,
                "keywords": keywords,
                "regex": regex,
                "attack_type": attack_type,
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8", errors="ignore")
    ).hexdigest()[:20]
    return {
        "rule_id": rule_id,
        "source": source,
        "attack_type": attack_type,
        "zones": zones,
        "tokens": tokens,
        "fingerprint": fp,
        "description": str(rule.get("description") or rule.get("name") or ""),
    }


def _public_node(node: dict[str, Any], *, accepted: bool, report: dict[str, Any]) -> dict[str, Any]:
    total_tp_gain = int(report.get("total_tp_gain") or 0)
    total_fp_increase = int(report.get("total_fp_increase") or 0)
    return {
        "id": node["rule_id"],
        "source": node["source"],
        "attack_type": node["attack_type"],
        "zones": list(node["zones"]),
        "token_count": len(node["tokens"]),
        "description": node["description"],
        "accepted": accepted,
        "metrics": {
            "total_tp_gain": total_tp_gain,
            "total_fp_increase": total_fp_increase,
            "mean_f1_gain": float(report.get("mean_f1_gain") or 0.0),
        },
        "governance_hint": _governance_hint(accepted, total_tp_gain, total_fp_increase),
    }


def _duplicate_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in nodes:
        groups[node["fingerprint"]].append(node)
    edges: list[dict[str, Any]] = []
    for items in groups.values():
        if len(items) < 2:
            continue
        root = items[0]
        for item in items[1:]:
            edges.append(
                {
                    "source": root["rule_id"],
                    "target": item["rule_id"],
                    "type": "duplicate",
                    "weight": 1.0,
                    "action": "merge_or_drop_duplicate",
                }
            )
    return edges


def _subsumption_edges(
    baseline_nodes: list[dict[str, Any]],
    candidate_nodes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for candidate in candidate_nodes:
        candidate_tokens = set(candidate["tokens"])
        candidate_zones = set(candidate["zones"])
        if not candidate_tokens:
            continue
        for base in baseline_nodes:
            base_tokens = set(base["tokens"])
            if not base_tokens:
                continue
            zone_overlap = not candidate_zones or not base["zones"] or bool(candidate_zones & set(base["zones"]))
            overlap = len(candidate_tokens & base_tokens)
            if zone_overlap and overlap >= max(2, min(len(candidate_tokens), 5)):
                edges.append(
                    {
                        "source": base["rule_id"],
                        "target": candidate["rule_id"],
                        "type": "subsumes",
                        "weight": round(overlap / max(1, len(candidate_tokens)), 4),
                        "action": "reject_or_require_incremental_gain",
                    }
                )
                break
    return edges


def _similarity_edges(candidate_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for idx, left in enumerate(candidate_nodes):
        for right in candidate_nodes[idx + 1:]:
            if left["attack_type"] != right["attack_type"]:
                continue
            if set(left["zones"]) and set(right["zones"]) and not (set(left["zones"]) & set(right["zones"])):
                continue
            sim = _jaccard(set(left["tokens"]), set(right["tokens"]))
            if sim >= 0.5:
                edges.append(
                    {
                        "source": left["rule_id"],
                        "target": right["rule_id"],
                        "type": "similar",
                        "weight": round(sim, 4),
                        "action": "consider_consolidation",
                    }
                )
    return edges


def _conflict_edges(
    candidate_nodes: list[dict[str, Any]],
    report_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for node in candidate_nodes:
        report = report_by_id.get(node["rule_id"]) or {}
        fp = int(report.get("total_fp_increase") or 0)
        if fp > 0:
            edges.append(
                {
                    "source": node["rule_id"],
                    "target": "benign_holdout",
                    "type": "conflict_fp",
                    "weight": fp,
                    "action": "scope_or_reject",
                }
            )
    return edges


def _contribution_edges(
    candidate_nodes: list[dict[str, Any]],
    report_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for node in candidate_nodes:
        report = report_by_id.get(node["rule_id"]) or {}
        tp = int(report.get("total_tp_gain") or 0)
        if tp > 0:
            edges.append(
                {
                    "source": node["rule_id"],
                    "target": "missed_attack_holdout",
                    "type": "contributes_tp",
                    "weight": tp,
                    "action": "keep_if_fp_stable",
                }
            )
    return edges


def _governance_hint(accepted: bool, tp_gain: int, fp_increase: int) -> str:
    if accepted:
        return "accepted_for_review"
    if fp_increase > 0:
        return "reject_or_scope_exception"
    if tp_gain <= 0:
        return "age_out_low_contribution"
    return "needs_more_holdout_validation"


def _summary(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    edge_counts: dict[str, int] = defaultdict(int)
    for edge in edges:
        edge_counts[str(edge.get("type"))] += 1
    candidate_nodes = [node for node in nodes if node["source"] == "candidate"]
    return {
        "candidate_count": len(candidate_nodes),
        "accepted_candidate_count": sum(1 for node in candidate_nodes if node.get("accepted")),
        "edge_type_counts": dict(sorted(edge_counts.items())),
    }


def _tokens(text: str) -> set[str]:
    ignored = {"query", "body", "path", "norm", "http", "https", "json", "regex"}
    return {
        match.group(0).lower()
        for match in _TOKEN_RE.finditer(text or "")
        if match.group(0).lower() not in ignored
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 0.0
    return len(left & right) / max(1, len(left | right))
