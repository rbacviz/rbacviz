# Benchmark baselines

These measurements were captured for Milestone 11 on Linux/amd64 with Go
1.25.12 and an Intel Xeon Platinum 8573C. Benchmarks used `-benchtime=500ms`.
They are not a promise that a cluster of a given size will fit a specific
latency or memory envelope. Hardware, Go patch version, graph shape, rule
matches, path bounds, and terminal dimensions materially change results.

| Workload | Fixture | Observed baseline |
| --- | --- | --- |
| Findings analysis | catalog benchmark fixture | 5.85 ms, 0.74 MB allocations |
| Attack-path analysis | synthetic benchmark fixture | 18.27 ms, 6.01 MB allocations |
| Full risk analysis | synthetic snapshot, 100 identities | 5.97 ms, 8.06 MB allocations |
| Semantic diff | two 100-identity snapshots, one Role changed | 78.72 ms, 26.87 MB allocations |
| Graph top-K traversal | large synthetic cyclic graph | 120.33 ms, 33.30 MB allocations |
| Permission resolution | resolver benchmark fixture | 1.90 ms, 2.01 MB allocations |
| Remediation | two fully simulated candidates | 2.15 ms, 1.33 MB allocations |
| Snapshot marshal | canonical benchmark fixture | 34.05 µs, 10.7 KB allocations |
| Cached TUI frame | 5,000 list items, visible window only | 0.265 ms, 137 KB allocations |

Run the current benchmark suite on the target machine:

```bash
go test -run '^$' -bench . -benchmem ./internal/permission ./internal/graph
go test -run '^$' -bench . -benchmem ./internal/attackpath ./internal/risk
go test -run '^$' -bench . -benchmem ./internal/diff ./internal/remediation ./internal/tui
```

Record the exact commit, `go version`, OS/architecture, CPU, query bounds, and
fixture generator beside any published result. Do not compare numbers collected
with different `MaxPaths`, `MaxExpanded`, terminal sizes, or snapshot shapes as
if they measured the same workload.

The release gate tracks determinism, cancellation, explicit truncation, and
absence of regressions that make ordinary use impractical. A public maximum
supported cluster size remains intentionally unspecified until representative
real-cluster evidence exists.
