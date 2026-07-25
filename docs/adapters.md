# WAF Adapters

GRAFT is WAF-agnostic. An adapter only needs to produce one prediction row for
each input request:

```json
{"sample_id":"sample-001","predicted":true}
```

Use `predicted=true` when the WAF blocks the request and `false` when it allows
the request. Preserve input order and stable IDs. Keep WAF execution,
containers, credentials, and vendor-specific configuration in a separate
repository or private deployment layer.
