# Contributing to rbacviz

Thank you for helping build an explainable Kubernetes security tool.

## Development requirements

- Go 1.25 or newer; use the patched release pinned by CI for security checks
- `golangci-lint` v2
- no live cluster is required for foundation tests

Before opening a pull request, run:

```bash
go mod tidy
gofmt -w .
go vet ./...
go test -race ./...
golangci-lint run
```

Keep domain and analysis packages independent from Cobra, terminal UI, and
Kubernetes client types. New user-visible commands must have working behavior
and deterministic tests; do not add placeholder commands.

Security-sensitive changes should include negative tests for secret leakage,
incomplete collection, or overconfident conclusions where applicable.

## Pull requests

Use focused commits, explain the user-visible security behavior, and include
tests for new invariants. Architectural changes should add or update an ADR.
