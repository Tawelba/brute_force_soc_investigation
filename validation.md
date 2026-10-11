# Detection validation

Reviewed 11 October 2026. The lab detection is experimental.

## Intended behavior

Select SSH messages containing `Failed password`, then count events for the same `host`, `src_ip` and `username`. The training threshold is at least four events within 60 seconds. Success events are not counted. Four legitimate password mistakes can also alert, so the output requires analyst triage.

The four-failure timeline in the incident report explains the chosen lab threshold. It was not used as a new raw-log capture. Every event passed to the local evaluator is explicitly synthetic, using a documentation IP and artificial timestamp; those fixtures are not original incident evidence.

## Reproduce local checks

Use a separate Python environment, install `requirements-validation.txt`, then run:

```text
python validate_detection.py
```

The script parses the collection using pySigma, checks local document/image links, and evaluates positive/negative cases using the actual YAML predicate, group fields, threshold and timespan. Results and tested package versions are in [validation-results.json](validation-results.json).

Checks cover the report-shaped positive fixture, below-threshold events, out-of-window events, separation by source/account/host, exclusion of successful and unrelated messages, window boundaries, unordered input, legitimate mistakes and missing grouping fields.

The small reference evaluator uses `(t - 60 seconds, t]` sliding windows. It is not a general Sigma interpreter, SIEM converter or proof of any backend's execution semantics.

## Remaining live acceptance work

1. Choose a correlation-capable backend and validate conversion using its supported processing pipeline.
2. Prove the ingestion parser supplies `message`, `host`, `src_ip` and `username` with consistent event timestamps. Do not count events with missing group fields as one shared group.
3. Replay authorized positive and negative fixtures through that backend; verify window boundaries, duplicates and late/out-of-order events.
4. Save the query, rule configuration and actual alert evidence. Tune the threshold for the environment rather than deploying this four-event training threshold unchanged.
5. Investigate successful authentication separately and document authorization, scope, session activity and response decisions.

No live alert, original-log replay, executed containment or production readiness is claimed by local validation.

## Specification reference

[Sigma correlation documentation](https://sigmahq.io/docs/meta/correlations.html) and the [correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html).
