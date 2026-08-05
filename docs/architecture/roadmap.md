# Roadmap, risks, and postponed decisions

## Implementation roadmap

### Milestone 1 — Foundation (completed)

- Go module and maintainable repository skeleton;
- Cobra root/version commands, config precedence, structured logging;
- typed application errors and exit-code mapping;
- unit tests, CI, formatting, vet, lint, license and contribution basics.

Acceptance: one binary builds on supported targets; `version` and help are
covered by deterministic tests; no empty user-visible commands are registered.

Delivered in the Milestone 1 implementation:

- Go module and a single process entry point; the minimum was raised from 1.24
  to 1.25 at release hardening so supported builds receive current standard
  library and `x/net`/`x/text` security fixes;
- working `version` and `config` commands with deterministic human/JSON output;
- configuration provenance and `defaults < file < environment < flags` precedence;
- typed application errors and stable process exit-code mapping;
- `slog` JSON logging without mutable global logger state;
- race-tested unit suites, vet, golangci-lint v2, and cross-platform CI builds;
- Apache-2.0 license, contribution guide, and security policy.

### Milestone 2 — Snapshot and collection (completed)

- client configuration, discovery, RBAC/workload/asset/control collectors;
- v1 snapshot types, validation, canonical JSON load/save;
- explicit partial-collection warnings and fake-client tests.

Acceptance: live metadata can be saved without Secret contents and reloaded to
the exact canonical semantic representation.

Delivered in the Milestone 2 implementation:

- kubeconfig/context-aware `client-go` clients and current-context namespace resolution;
- preferred API discovery with partial-discovery warnings;
- Role, ClusterRole, binding, subject, ServiceAccount, and identity collection;
- Pod, Deployment, DaemonSet, StatefulSet, Job, and CronJob security metadata;
- metadata-only collection for Secrets and other security-relevant assets;
- Pod Security Admission, admission policy/webhook, Kyverno, and Gatekeeper observations;
- versioned schema v1, stable IDs, canonical ordering, validation, and semantic digest;
- atomic owner-only JSON save/load with incompatible-version and sensitive-field rejection;
- `snapshot save`, `snapshot inspect`, JSON summaries, and strict partial exit code 3;
- fake-client, credential-leakage, canonical round-trip, CLI, race, vet, and lint tests.

### Milestone 3 — Permissions (completed)

- aggregation fixed point, binding resolver, capability matcher;
- `permissions`, `who-can`, and `why-can` with full grant provenance;
- unit/fuzz tests and normalization benchmarks.

Acceptance: live and offline snapshots produce the same deterministically
ordered permission results; every matching capability retains every independent
binding, role, rule, subject, and aggregation path that grants it.

Delivered in the Milestone 3 implementation:

- immutable resolver indexes over canonical snapshot v1 input;
- Kubernetes label-selector evaluation and cycle-safe ClusterRole aggregation;
- stale materialized aggregate rules are ignored and recomputed from selectors;
- exact RoleBinding/ClusterRoleBinding scope semantics, including ClusterRole
  references from namespaced RoleBindings;
- explicit wildcard, subresource, `resourceNames`, and non-resource URL matching;
- explicit `--as-group` membership without inventing user-to-group relationships;
- versioned deterministic JSON and evidence-rich human output;
- resolver warnings for missing role references, aggregation cycles, invalid
  selectors, unknown resource scope, and inherited collection gaps;
- unit and fuzz coverage for the required permission matrix plus normalization
  benchmarks and offline CLI contract tests.

### Milestone 4 — Graph (completed)

- typed multigraph, indexes, lazy selectors, traversal and top-K paths;
- cyclic/large synthetic fixtures and benchmarks.

Acceptance: the same canonical snapshot produces stable graph identities and
deterministic traversal results; every edge has evidence; top-K search is
loopless, weighted, cancellable, and bounded by depth and expanded candidates.

Delivered in the Milestone 4 implementation:

- immutable typed directed multigraph with stable portable node and edge IDs;
- compact ID, key, type, incoming-edge, and outgoing-edge indexes;
- identity, RBAC, lazy resource-selector, workload, asset, namespace, and
  security-control graph construction;
- complete RBAC grant provenance on `BOUND_BY`, `GRANTS`, `ALLOWS`, and
  `REACHES` transitions;
- structural `RUNS_AS`, `OWNS`, and `MOUNTS` relationships with object/field
  evidence;
- indexed node selectors plus deterministic bounded breadth-first traversal;
- non-negative top-K loopless path search ordered by cost, length, and stable
  identity, with context cancellation and explicit truncation;
- working `graph stats`, `graph nodes`, and `graph paths` human/JSON commands;
- deterministic, cycle, hard-limit, offline CLI, and large synthetic benchmark
  coverage.

### Milestone 5 — Findings (completed)

- stable rule interfaces and a versioned 32-rule built-in catalog;
- evidence-backed finding model with stable content-derived IDs;
- deterministic human, JSON, and SARIF 2.1.0 output;
- `findings` severity/rule/namespace filters and `explain <finding-id>`;
- incomplete-collection propagation, cancellation, isolated rule tests, and
  offline CLI contracts.

Acceptance: identical normalized snapshots and rule sets produce byte-stable
finding IDs and ordering; every finding has exact RBAC grant or object-field
evidence; partial collection remains visible; SARIF contains stable
fingerprints and the complete finding payload.

### Milestone 6 — Attack paths (completed)

- attack templates and typed privilege targets;
- prerequisites, confidence composition, and mitigation observations;
- bounded path ranking and `attack-path` CLI.

Acceptance: the same canonical snapshot and template set produce stable path
IDs and total ordering; every path contains exact RBAC provenance, explicit
prerequisites, observation-bounded controls and confidence reasons; filtering
and expansion limits cannot silently claim exhaustive results.

Delivered in the Milestone 6 implementation:

- versioned `1.0.0` catalog of 12 attack templates and 12 typed privilege
  targets, including direct administration, identity takeover, RBAC control,
  node control, persistence, and host escape;
- stable content-derived path and step IDs plus ordered identity → technique →
  privilege-target transitions;
- exact normalized permission, policy rule, role, binding, subject, scope, and
  object-field evidence on enabling steps;
- explicit satisfied, required, and unknown prerequisites;
- known Pod Security Admission evaluation for modeled host escape and
  conservative potential-mitigation handling for uninterpreted admission
  webhooks, ValidatingAdmissionPolicy, Kyverno, and Gatekeeper;
- categorical confidence composition with partial-collection and unknown-scope
  propagation;
- documented additive path costs and deterministic ranking with blocked paths
  retained separately for explanation;
- `attack-path --from --to --namespace --top --max-expanded` human/JSON output;
- unit, offline CLI, fuzz, cancellation, determinism, hard-limit, and benchmark
  coverage.

### Milestone 7 — Risk (completed)

- transparent factor scoring and explanations;
- identity, namespace, and cluster aggregation;
- calibrated deterministic fixtures.

Acceptance: the same bounded attack-path result produces byte-stable scores and
ordering; every path exposes all factor inputs and exact integer arithmetic;
duplicate grant paths cannot inflate a semantic risk unit; incomplete or
truncated analysis cannot appear exhaustive.

Delivered in the Milestone 7 implementation:

- versioned risk result schema `1.0` and scoring model `1.0.0`;
- six normalized path factors with fixed integer weights and source explanations;
- exact basis-point scope and mitigation adjustments with one final rounding;
- categorical confidence mappings and retained underlying impact for blocked paths;
- stable path-risk IDs, severity bands, and deterministic total ordering;
- semantic risk-unit deduplication across parallel grants without dropping path IDs;
- saturating identity, namespace, and cluster aggregation against remaining headroom;
- namespace- and identity-scoped analysis with bounded path expansion;
- `risk --identity --namespace --top --max-paths --max-expanded` human/JSON output;
- calibrated fixtures, invariant fuzzing, cancellation, determinism, duplicate,
  incomplete-collection, offline CLI, and benchmark coverage.

### Milestone 8 — TUI (completed)

- responsive shell, overview and core inspectors;
- navigation, progress, cancellation, search/filter/sort;
- golden render tests at representative terminal sizes.

Acceptance: the same immutable application results drive CLI and TUI answers;
large lists render a bounded visible window; detailed path evidence is loaded
only on demand; loading and path analysis are cancellable; filters and selection
survive navigation; representative layouts remain deterministic.

Delivered in the Milestone 8 implementation:

- Bubble Tea shell with Bubbles spinner, text input, and scrollable viewports;
- responsive one-, two-, and three-panel layouts at the documented breakpoints;
- ten implemented views without placeholders for future diff/simulation work;
- central configurable keymap and keyboard-first navigation;
- per-view selection, search, filters, sorting, pagination offset, and inspector state;
- staged snapshot, graph, findings, and risk loading with visible cancellation;
- lazy, bounded, independently cancellable detailed attack-path materialization;
- persistent partial-collection, analysis-warning, and truncation indicators;
- advisory evidence/remediation modals backed only by existing engine results;
- deterministic no-color golden render coverage at 72x24, 100x30, and 140x34;
- cancellation, lazy loading, state preservation, and 5,000-item virtualization tests.

### Milestone 9 — Diff and simulation (completed)

- canonical object and identity diff;
- semantic effective-permission and provenance diff;
- findings, attack-path, control, and risk comparison;
- safe manifest overlay and what-if analysis.

Acceptance: diff output is byte-stable for identical normalized inputs and
distinguishes new access from redundant grant churn; bounded analysis never
appears exhaustive; simulation operates only on an in-memory snapshot copy,
never calls or mutates a cluster, and cannot persist Secret payloads.

Delivered in the Milestone 9 implementation:

- versioned semantic diff and simulation result schemas `1.0`;
- canonical added/removed/modified object inventory plus observed identities;
- effective capability comparison with independent grant additions/removals;
- security classification for new wildcard, Secret, workload mutation, token,
  impersonation, and RBAC-control capabilities;
- finding and semantic attack-path additions/removals plus confidence,
  blocking, cost, and mitigating-control changes;
- exact cluster, namespace, and identity risk deltas;
- deterministic recursive YAML/JSON manifest loading with `List` support;
- full-object upsert and explicit annotation-based delete overlays for RBAC,
  ServiceAccounts, workloads, assets, PSA, admission, Kyverno, and Gatekeeper;
- mandatory offline `simulate -s ... -f ...` with no live fallback or apply path;
- Secret payload discard, unsupported-kind rejection, cancellation, CLI,
  determinism, duplicate-grant, deletion, directory-order, fuzz, and benchmark
  coverage.

### Milestone 10 — Remediation (completed)

- generate structured remediation candidates;
- virtually apply and measure each candidate;
- calculate affected paths and permission impact;
- Pareto filter and deterministically rank security benefit versus cost;
- add the remediation simulation panel to the TUI.

Acceptance: every recommendation is produced from an isolated snapshot clone,
shows measurable path or risk improvement, reports permission loss and affected
identities, and is Pareto-ranked with a stable ID. Redundant-grant churn cannot
be recommended as effective remediation, bounded analysis cannot appear
complete, and no cluster mutation interface exists.

Delivered in the Milestone 10 implementation:

- versioned remediation result schema `1.0` and ranking model `1.0.0`;
- structured exact-subject removal, source-rule verb narrowing, and supported
  restricted PSA candidates derived from attack-path evidence;
- deep-copy virtual application with full permission, finding, attack-path,
  control, and risk re-analysis for every candidate;
- measured removed/blocked/remaining paths, lost effective capabilities,
  affected identities, provenance-only changes, and exact scoped risk deltas;
- explicit security-benefit and operational-cost components with deterministic
  basis-point ratio, Pareto filtering, stable IDs, and total ordering;
- `RECOMMENDED`, `DOMINATED`, and `INEFFECTIVE` dispositions, including
  redundant-grant detection and incomplete-analysis uncertainty penalties;
- `remediate` human/JSON CLI with identity, namespace, candidate, path, and
  expansion bounds;
- lazy, independently cancellable TUI remediation simulation panel;
- determinism, isolation, redundant-grant, PSA, bounds, cancellation, offline
  CLI, fuzz, benchmark, race, vet, lint, and cross-build coverage.

### Milestone 11 — Release (completed)

- full documentation, threat model, examples, real screenshots;
- race/static/vulnerability checks, measured benchmarks;
- reproducible multi-platform archives, checksums and SBOM.

Acceptance: security boundaries and residual risks are explicit; every example
is synthetic and regression-tested; screenshots are generated by the real TUI;
the same source, toolchain, commit, and `SOURCE_DATE_EPOCH` produce byte-identical
artifacts; consumers receive checksums, build metadata, a CycloneDX SBOM, and
provenance for all supported targets.

Delivered in the Milestone 11 implementation:

- formal threat model covering assets, trust boundaries, abuse cases, privacy,
  denial-of-service bounds, unknown controls, and advisory remediation risk;
- synthetic token-minter, blocked host-escape, and incomplete-collection examples;
- deterministic SVG documentation captures generated from the real TUI model;
- measured benchmark methodology and honest no-size-claim baseline table;
- atomic deterministic tar.gz and ZIP packaging for five supported targets;
- normalized archive order, modes, owners, timestamps, Go build IDs, and paths;
- CycloneDX 1.5 Go module SBOM, release manifest, and SHA-256 checksums;
- independent double-build byte-reproducibility verification;
- CI dependency review, govulncheck, generated-asset drift detection, release
  checksum verification, provenance attestation, and tag-gated publication;
- expanded security policy and documented consumer verification process.

## Technical risks and controls

| Risk | Consequence | Control |
| --- | --- | --- |
| Incomplete collector privileges | false sense of safety | explicit warnings, completeness propagation, strict mode |
| RBAC aggregation mismatch | incorrect permissions | selector fixed point, provenance, API fixtures |
| Combinatorial graph expansion | excessive memory/runtime | selector nodes, lazy expansion, bounded top-K search |
| Arbitrary webhook semantics | false blocked/allowed claims | observation-only state unless evaluator is implemented |
| Group membership unknowable | missing user permissions | explicit supplied groups; never infer membership |
| API discovery unavailable | wrong resource scope | retain unknown scope and lower confidence |
| Secret leakage | credential exposure | schema forbids values; redaction tests and log review |
| Snapshot schema churn | broken offline workflows | versioned schema and pure migrations |
| Score perceived as arbitrary | low trust | factor breakdown, versioned constants, fixture calibration |
| Remediation breaks workloads | operational harm | advisory-only simulation and permission-impact reporting |
| TUI diverges from CLI | inconsistent answers | shared application result/query layer |
| Tests require a real cluster | slow/flaky CI | fake clients first; isolated kind integration suite |

## Decisions postponed until after MVP evidence

- exact large-cluster support claim and default concurrency values;
- cloud-provider IAM correlation;
- audit-log identity discovery;
- full Kyverno/Gatekeeper policy interpretation;
- SubjectAccessReview verification UX beyond individual queries;
- plugin/rule extension ABI;
- HTML/browser report;
- daemon or continuous monitoring mode;
- persistence/database beyond snapshot files;
- automatic remediation application;
- final public `pkg/api` surface beyond snapshot/results needed by integrations;
- score calibration constants beyond the transparent initial proposal;
- bidirectional graph query language.

These are postponed because premature commitments would either expand the
threat model, freeze an unstable API, or require performance/usage evidence not
available before a working MVP.

## Milestone 0 exit criteria

- domain language and sensitive-data boundary are explicit;
- live, offline, diff, and simulation share one snapshot-analysis pipeline;
- package dependency direction is enforceable;
- permissions retain every independent grant as evidence;
- graph types, confidence states, ranking, scoring, and remediation simulation
  have deterministic contracts;
- CLI hierarchy and TUI navigation are mapped;
- high-risk unknowns have a planned control or are explicitly postponed.
