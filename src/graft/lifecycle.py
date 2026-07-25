"""Rule lifecycle utilities for GRAFT."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9_.$:-]{3,}", re.IGNORECASE)


@dataclass(slots=True)
class RuleLifecycleReport:
    generated_at: float = field(default_factory=time.time)
    accepted_total: int = 0
    rejected_total: int = 0
    duplicate_candidates: list[dict[str, Any]] = field(default_factory=list)
    subsumed_candidates: list[dict[str, Any]] = field(default_factory=list)
    high_fp_candidates: list[dict[str, Any]] = field(default_factory=list)
    low_contribution_candidates: list[dict[str, Any]] = field(default_factory=list)
    consolidation_groups: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "accepted_total": self.accepted_total,
            "rejected_total": self.rejected_total,
            "duplicate_candidates": self.duplicate_candidates,
            "subsumed_candidates": self.subsumed_candidates,
            "high_fp_candidates": self.high_fp_candidates,
            "low_contribution_candidates": self.low_contribution_candidates,
            "consolidation_groups": self.consolidation_groups,
        }


def build_lifecycle_report(
    *,
    baseline_entries: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    accepted: list[dict[str, Any]],
    regression_report: list[dict[str, Any]],
    min_total_tp_gain: int,
    max_total_fp_increase: int,
) -> RuleLifecycleReport:
    accepted_ids = {str(item.get("rule_id")) for item in accepted}
    baseline_signatures = [_rule_signature(item) for item in baseline_entries]
    candidate_signatures = [_rule_signature(item) for item in candidates]
    report_by_id = {str(item.get("rule_id")): item for item in regression_report}

    lifecycle = RuleLifecycleReport(
        accepted_total=len(accepted),
        rejected_total=max(0, len(candidates) - len(accepted)),
    )

    seen: dict[str, str] = {}
    for candidate, signature in zip(candidates, candidate_signatures, strict=False):
        rule_id = str(candidate.get("rule_id"))
        fingerprint = signature["fingerprint"]
        if fingerprint in seen:
            lifecycle.duplicate_candidates.append(
                {
                    "rule_id": rule_id,
                    "duplicates_rule_id": seen[fingerprint],
                    "reason": "same zone/regex/token fingerprint",
                }
            )
        else:
            seen[fingerprint] = rule_id

        subsumed_by = _find_subsuming_rule(signature, baseline_signatures)
        if subsumed_by:
            lifecycle.subsumed_candidates.append(
                {
                    "rule_id": rule_id,
                    "subsumed_by": subsumed_by,
                    "reason": "candidate tokens/zones are already covered by baseline rule",
                }
            )

        regression = report_by_id.get(rule_id) or {}
        total_tp_gain = int(regression.get("total_tp_gain") or 0)
        total_fp_increase = int(regression.get("total_fp_increase") or 0)
        if total_fp_increase > max_total_fp_increase:
            lifecycle.high_fp_candidates.append(
                {
                    "rule_id": rule_id,
                    "total_fp_increase": total_fp_increase,
                    "action": "reject_or_scope_exception",
                }
            )
        if rule_id not in accepted_ids and total_tp_gain < min_total_tp_gain:
            lifecycle.low_contribution_candidates.append(
                {
                    "rule_id": rule_id,
                    "total_tp_gain": total_tp_gain,
                    "action": "age_out_or_merge",
                }
            )

    lifecycle.consolidation_groups = _build_consolidation_groups(candidates)
    return lifecycle


def write_lifecycle_report(path: Path, report: RuleLifecycleReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _rule_signature(rule: dict[str, Any]) -> dict[str, Any]:
    zones = tuple(sorted(str(item).strip().lower() for item in rule.get("match_zone") or [] if str(item).strip()))
    regex = str(rule.get("regex") or rule.get("detection_pattern") or "").strip().lower()
    keywords = tuple(sorted(str(item).strip().lower() for item in rule.get("ac_keywords") or [] if str(item).strip()))
    tokens = tuple(sorted(_tokens(regex) | set(keywords)))
    attack_type = str(rule.get("attack_type") or rule.get("family") or "").strip().lower()
    fingerprint_input = json.dumps(
        {"zones": zones, "regex": regex, "keywords": keywords, "attack_type": attack_type},
        ensure_ascii=False,
        sort_keys=True,
    )
    return {
        "rule_id": str(rule.get("rule_id") or rule.get("id") or ""),
        "zones": zones,
        "regex": regex,
        "tokens": tokens,
        "attack_type": attack_type,
        "fingerprint": hashlib.sha256(fingerprint_input.encode("utf-8", errors="ignore")).hexdigest()[:20],
    }


def _tokens(text: str) -> set[str]:
    ignored = {"query", "body", "path", "norm", "http", "https", "regex", "json"}
    return {
        match.group(0).lower()
        for match in _TOKEN_RE.finditer(text)
        if match.group(0).lower() not in ignored
    }


def _find_subsuming_rule(candidate: dict[str, Any], baseline: list[dict[str, Any]]) -> str:
    candidate_tokens = set(candidate["tokens"])
    candidate_zones = set(candidate["zones"])
    if not candidate_tokens:
        return ""
    for item in baseline:
        base_tokens = set(item["tokens"])
        base_zones = set(item["zones"])
        if not base_tokens:
            continue
        zone_ok = not candidate_zones or not base_zones or candidate_zones.issubset(base_zones) or bool(candidate_zones & base_zones)
        token_overlap = len(candidate_tokens & base_tokens)
        if zone_ok and token_overlap >= max(2, min(len(candidate_tokens), 5)):
            return str(item["rule_id"])
    return ""


def _build_consolidation_groups(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        signature = _rule_signature(candidate)
        key = (signature["attack_type"], signature["zones"])
        groups[key].append(signature)

    output: list[dict[str, Any]] = []
    for (attack_type, zones), items in groups.items():
        if len(items) < 2:
            continue
        shared = set(items[0]["tokens"])
        for item in items[1:]:
            shared &= set(item["tokens"])
        output.append(
            {
                "attack_type": attack_type or "unknown",
                "zones": list(zones),
                "rule_ids": [item["rule_id"] for item in items],
                "shared_tokens": sorted(shared)[:20],
                "recommendation": "consider merging if replay metrics stay stable",
            }
        )
    return output[:50]
