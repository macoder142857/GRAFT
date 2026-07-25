# Architecture

GRAFT separates discovery, synthesis, governance, and measurement.

1. **Discover.** Read label-free development requests and aligned decisions
   from a target WAF. Allowed requests with recognizable attack structure form
   target-relative blind-spot seeds.
2. **Expand.** Apply bounded, family-aware mutations to expose encoding,
   syntax, parameter, and protocol variants while retaining request context.
3. **Synthesize.** Send batched multi-view evidence to an OpenAI-compatible
   model. The model returns structured Boolean rules with explicit zones,
   transforms, positive conditions, and exclusions.
4. **Validate and govern.** Replay each candidate on a disjoint labeled
   validation split. Admit rules only when they add true-positive coverage
   within the configured false-positive budget. Duplicate contribution vectors
   are removed and rule relationships are recorded in a contribution graph.
5. **Freeze and measure.** Freeze the accepted set before opening held-out test
   labels. Report baseline and enhanced predictions, metrics, family recall,
   input hashes, lifecycle state, and graph artifacts.

The target WAF remains unchanged. GRAFT combines its original decision with
the frozen rule layer using logical OR.
