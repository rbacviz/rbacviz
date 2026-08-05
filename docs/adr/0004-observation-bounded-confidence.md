# ADR 0004: Confidence is bounded by observable controls

- Status: accepted
- Date: 2026-08-05

## Decision

Admission controls affect path confidence only to the extent that their
semantics are implemented and their relevant configuration was collected.
Unknown webhook, Kyverno, or Gatekeeper semantics are reported as uncertainty,
not proof that a path is blocked.

## Rationale

False claims of exploitability or protection undermine the core promise of
explainability. Explicit uncertainty is safer and more accurate.

## Consequences

Some paths remain `UNKNOWN` or `CONDITIONAL` even when operators know an
external control is effective. Future evaluators can improve confidence without
changing the underlying model.

