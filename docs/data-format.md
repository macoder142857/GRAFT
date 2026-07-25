# Data Format

All files are UTF-8 JSONL unless stated otherwise. Files within a split must
have the same number and order of rows.

## Request rows

Labels should be stored separately during selection.

```json
{"sample_id":"sample-001","raw_log":"GET /search?q=test HTTP/1.1\nHost: example.test\n\n"}
```

GRAFT also accepts structured fields such as `request_target`, `url`,
`req_data.query`, `req_data.body`, `req_data.headers`, and their equivalents
inside a `request` object.

## Prediction rows

```json
{"sample_id":"sample-001","predicted":false}
```

`outcome` with value `block` or `allow` is also accepted.

## Label rows

```json
{"sample_id":"sample-001","label":true,"attack_family":"xss"}
```

`label=true` means malicious. Benign rows may use `attack_family="benign"`.

## Candidate cache

A candidate cache is a JSON array or JSONL file containing structured GRAFT
rules. It is useful for deterministic replay and does not require API
credentials. Candidate caches must use `"source_file": "graft_offline_llm"`.
