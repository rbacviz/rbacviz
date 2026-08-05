# ADR 0002: Canonical snapshot as the analysis input

- Status: accepted
- Date: 2026-08-05

## Decision

All analysis consumes a validated canonical snapshot. Live collection,
snapshot loading, diff, simulation, and remediation produce or overlay that
same model.

## Rationale

One input contract makes live and offline results reproducible, enables focused
fixtures, and prevents alternate analysis implementations from emerging.

## Consequences

The snapshot schema becomes a security-sensitive compatibility boundary and
needs strict validation, migration, and sensitive-field tests.

