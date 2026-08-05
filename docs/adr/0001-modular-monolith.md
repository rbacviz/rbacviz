# ADR 0001: Modular monolith and inward dependencies

- Status: accepted
- Date: 2026-08-05

## Decision

Build one Go binary as a modular monolith. Domain and analysis packages remain
independent of Kubernetes clients, Cobra, Bubble Tea, and output formats.

## Rationale

The product requires offline deterministic analysis and simple distribution.
External services would add operational dependencies without solving an MVP
requirement. Inward dependencies keep algorithms unit-testable.

## Consequences

Package boundaries require explicit translation at adapters. This modest cost
prevents framework types and I/O behavior from contaminating core analysis.

