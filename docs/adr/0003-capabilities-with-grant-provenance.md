# ADR 0003: Capabilities retain independent grant provenance

- Status: accepted
- Date: 2026-08-05

## Decision

Normalize effective permissions into typed capabilities while retaining every
binding, role, rule, and aggregation chain that grants each capability.

## Rationale

Permission deduplication alone cannot explain access or determine whether a
proposed binding removal actually revokes it. Provenance is required for
`why-can`, attack-step evidence, and remediation simulation.

## Consequences

The model is larger than a flat permission set. Indexing and stable evidence
deduplication are required, but eager object-level graph expansion remains
unnecessary.

