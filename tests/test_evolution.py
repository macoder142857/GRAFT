from __future__ import annotations

import json

import pytest

from graft import evolution


def test_evidence_batching_keeps_every_unique_long_sample() -> None:
    rows = [
        {
            "payload": f"/search?q={'a' * 900}{index:03d}",
            "attack_class": "sqli",
            "source": "test",
        }
        for index in range(40)
    ]

    batches, report = evolution._evidence_batches(rows, char_budget=5000)

    assert report["unique_evidence_count"] == 40
    assert sum(len(samples) for _family, samples in batches) == 40
    assert len(batches) > 1
    assert max(
        len(json.loads(sample)["payload"])
        for _family, samples in batches
        for sample in samples
    ) > 240


def test_structured_rule_requires_cross_field_all_of() -> None:
    raw = json.dumps(
        [
            {
                "description": "SQL intent combined with a privileged header",
                "family": "cross_field_sqli",
                "fast_pattern": ["select", "x-admin"],
                "match_zone": ["query_norm", "headers_norm"],
                "transform_chain": ["lowercase", "recursive_decode"],
                "logic": {
                    "all_of": [
                        {
                            "match_zone": ["query_norm"],
                            "transform_chain": ["lowercase", "recursive_decode"],
                            "regex": r"select\s+.+\s+from",
                            "purpose": "SQL structure",
                        },
                        {
                            "match_zone": ["headers_norm"],
                            "transform_chain": ["lowercase"],
                            "regex": r"x-admin\s*:\s*1",
                            "purpose": "privileged execution context",
                        },
                    ],
                    "any_of": [],
                    "none_of": [],
                },
                "action": "block",
            }
        ]
    )
    rule = evolution._normalise_llm_rule(
        evolution._validate_llm_rules(raw)[0],
        240000,
    )
    rows = [
        {
            "raw_log": (
                "GET /search?q=select%20name%20from%20users HTTP/1.1\n"
                "Host: example.test\nX-Admin: 1\n\n"
            )
        },
        {
            "raw_log": (
                "GET /search?q=select%20name%20from%20users HTTP/1.1\n"
                "Host: example.test\n\n"
            )
        },
        {
            "raw_log": (
                "GET /search?q=hello HTTP/1.1\nHost: example.test\nX-Admin: 1\n\n"
            )
        },
    ]

    assert evolution._matches(rows, rule) == [True, False, False]


def test_family_is_open_ended() -> None:
    raw = json.dumps(
        [
            {
                "description": "GraphQL alias amplification",
                "family": "graphql_alias_amplification",
                "match_zone": ["body_norm"],
                "transform_chain": ["lowercase"],
                "fast_pattern": ["query"],
                "regex": r"(?:\w+\s*:\s*){4,}\w+\s*\(",
                "action": "block",
            }
        ]
    )

    rule = evolution._validate_llm_rules(raw)[0]

    assert rule["family"] == "graphql_alias_amplification"
    assert rule["execution_semantics"] == "structured_boolean_v1"


def test_empty_boolean_groups_fall_back_to_top_level_regex() -> None:
    rule = {
        "rule_id": 1,
        "match_zone": ["query_values_norm"],
        "regex": r"<\s*script\b",
        "transforms": ["lowercase", "recursive_decode"],
        "logic": {"all_of": [], "any_of": [], "none_of": []},
    }
    rows = [
        {
            "raw_log": (
                "GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
                "Host: example.test\n\n"
            )
        },
        {"raw_log": "GET /?q=hello HTTP/1.1\nHost: example.test\n\n"},
    ]

    assert evolution._matches(rows, rule) == [True, False]


def test_pathological_regex_is_stopped() -> None:
    matcher = evolution._TimedRegex(r"^(?:a|aa)+$")

    with pytest.raises(evolution.RuleExecutionTimeout):
        matcher.search("a" * 10000 + "!")


def test_single_view_ablation_uses_primary_zone() -> None:
    rule = {
        "field": "query_values_norm",
        "match_zone": ["query_values_norm", "body_values_norm"],
        "transforms": ["lowercase", "recursive_decode"],
        "logic": {
            "all_of": [
                {
                    "match_zone": ["headers_norm"],
                    "transforms": ["lowercase"],
                    "regex": r"x-admin\s*:\s*1",
                }
            ],
            "any_of": [],
            "none_of": [],
        },
    }

    reduced = evolution._single_view_rule(rule)

    assert reduced["match_zone"] == ["query_values_norm"]
    assert reduced["logic"]["all_of"][0]["match_zone"] == ["query_values_norm"]
    assert rule["logic"]["all_of"][0]["match_zone"] == ["headers_norm"]
