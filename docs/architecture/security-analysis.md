# Attack paths, risk, and remediation

## Findings and attack templates

Rules are small, independently testable evaluators with stable IDs. A finding
contains evidence and may seed one or more attack templates. Templates declare:

- admissible source and target node types;
- required capability predicates;
- structural transitions;
- prerequisites;
- mitigation evaluators;
- privilege target type;
- base step cost and confidence rules.

Template set `1.0.0` covers direct `cluster-admin`, `system:masters`, workload
identity takeover, ServiceAccount token creation, Secret-to-identity inference,
`bind`, `escalate`, binding mutation, impersonation, node proxy, CSR approval,
and host escape. Template IDs, step IDs, and path IDs are stable and derived
from semantic content rather than collection timestamps or slice order.

Milestone 5 ships ruleset `1.0.0` with 32 built-in rules. The engine
canonicalizes one snapshot, resolves permissions once for every observed
identity, then evaluates each rule in stable rule-ID order. A finding ID is a
hash of the stable rule ID and the rule-specific semantic target; collection
timestamps and input list order cannot change it. Findings are ordered by
static rule risk, rule ID, and finding ID.

The initial `riskScore` on a finding is a documented rule classification used
for ordering and SARIF security severity. It is not the aggregate risk model;
factor-based path, identity, namespace, and cluster scoring remains Milestone 7.
Rules only claim directly observed RBAC grants or workload fields. The
Milestone 6 engine turns a primitive into an attack path only after matching a
versioned template, recording every prerequisite, and evaluating observable
controls within its supported semantics.

## Admission-aware confidence

Confidence is a state with reasons, not a numeric probability.

| State | Meaning |
| --- | --- |
| `CONFIRMED` | All modeled steps and required configuration are directly observed |
| `LIKELY` | RBAC chain is present; runtime state is not fully observable |
| `CONDITIONAL` | An explicit additional prerequisite is required |
| `BLOCKED` | An observed, semantically evaluated control blocks a required step |
| `UNKNOWN` | Missing collection data or an uninterpreted external control is material |

Path confidence is the most restrictive material step state, with `BLOCKED`
winning when a required transition is blocked. Uninterpreted webhooks, Kyverno
policies, and Gatekeeper constraints are recorded as potential mitigations and
usually produce `UNKNOWN` or `CONDITIONAL`, never a claim of enforcement.

## Path search and ranking

The initial engine uses permission and object indexes to materialize only
template candidates matching the selected source, target, and namespace.
Identity → technique → privilege-target paths are loopless by construction.
Candidate expansion and result count have hard limits; context cancellation and
the command timeout bound runtime. Later cross-technique composition can reuse
the general graph top-K pathfinder without changing the result contract.

Each step cost is derived from documented factors:

```text
stepCost =
    baseTechniqueCost
  + prerequisitePenalty
  + uncertaintyPenalty
  + mitigationPenalty
  + operationalComplexity
```

Path ranking uses the summed step cost, then higher privilege gain, larger
blast radius, higher confidence, shorter length, and stable path ID as total
ordering tie-breakers. `BLOCKED` paths are retained for explanation but ranked
separately from exploitable candidates.

This prevents a merely short theoretical chain from outranking a longer,
well-evidenced and more practical chain.

## Risk scoring model `2.0.0`

Severity and risk score are separate. Every score includes raw factors,
weights, mitigation deductions, and the final normalization.

Base factors use a 0–100 scale:

| Factor | Weight | Source |
| --- | ---: | --- |
| Impact | 0.30 | typed privilege target |
| Exploitability | 0.22 | template and required operations |
| Blast radius | 0.18 | reachable namespaces/assets/identities |
| Exposure | 0.10 | identity/workload usage and reachability |
| Path quality | 0.10 | evidence completeness and complexity |
| Confidence | 0.10 | explicit state mapping |

Model `2.0.0` preserves the calibrated path factors from `1.0.0` and derives
those values without hidden state. The version change identifies the new
root-cause-family aggregate, not a silent change to individual path weights:

- impact and blast radius come from the versioned typed privilege target;
- exploitability starts at 100 and deducts eight points for each modeled base,
  prerequisite, and operational-complexity cost unit;
- exposure is 60 for directly bound users, 70 for groups, and 45 plus ten per
  observed ServiceAccount workload, capped at 80;
- path quality starts at 50, adds 15 for normalized permission evidence, 20
  for exact grant provenance, and 10 for object evidence, then deducts 15 for
  each required and 25 for each unknown prerequisite;
- confidence uses the fixed mapping below.

Every factor is clamped to `0..100` and carries its source explanation in JSON.

The weighted base is multiplied by a scope factor in `[0.85, 1.15]`, then
reduced by evaluated mitigating-control effectiveness. All implementation
arithmetic uses integer weights and basis points. The final score is rounded
once and clamped to `0..100`.

```text
base = weightedMean(factors)
adjusted = base * scopeFactor
score = clamp(round(adjusted * (1 - mitigationEffect)), 0, 100)
```

Confidence mappings are `CONFIRMED=100`, `LIKELY=85`, `CONDITIONAL=60`,
`UNKNOWN=35`, and `BLOCKED=20`. A `BLOCKED` path keeps its underlying impact
visible but receives a 90% evaluated mitigation reduction and the `BLOCKED`
label. Potential uninterpreted controls deduct 10% each, capped at 30%; observed
controls without evaluated effectiveness deduct nothing.

Suggested severity bands for MVP:

- `CRITICAL`: 85–100
- `HIGH`: 70–84
- `MEDIUM`: 40–69
- `LOW`: 1–39
- `INFO`: 0 or non-risk informational observations

Cluster, namespace, and identity risk are not simple sums. Model `2.0.0` first
groups derivative paths into a root-cause family keyed by the exact RBAC
binding and subject. The highest path represents the family; other techniques
and targets remain evidence but cannot increase that family's score. Families
with the same complete set of semantic risk units are retained as separate
remediation roots, but only one deterministic representative contributes to
the aggregate.

The aggregate starts with the highest semantically distinct family at 100%.
At most five additional families contribute at ranked weights `5/3/2/1/1%`.
Their combined contribution is capped at `+12`, and the final index remains
bounded at 100. JSON exposes every family, semantic key, selected contributor,
weight, and integer contribution. Thus raw path count, a wildcard rule that
generates many targets, and redundant equivalent bindings cannot rapidly
saturate the posture index.

`100/100` is reserved for a primary family already scored at 100 or for enough
independent high-risk families to fill the remaining headroom. It is still a
posture index, never breach probability.

Cluster-impact paths are attributed to every namespace actually observed in
the snapshot inventory. They are not expanded to guessed or inaccessible
namespaces. Namespace-scoped results therefore preserve global compromise paths
without pretending that partial collection is complete.

## Semantic comparison and operator-supplied simulation

Diff schema `1.0` compares canonical object presence and content first, then
runs the same permission, finding, attack-path, and risk engines independently
on both inputs. Permission selectors exclude grants from their semantic key, so
a second equivalent binding is reported as provenance change rather than new
authority. Attack paths use source, template, and privilege-target keys for the
same reason; their representative path ID remains available as evidence.

Both sides retain completeness warnings and use the same explicit path and
candidate bounds. If either analysis truncates, the comparison is marked
`truncated` and cannot be `complete`. Risk deltas preserve exact before/after
scores and severities rather than recomputing a hidden comparison score.

Simulation schema `1.0` parses the operator's YAML/JSON manifests, converts only
the fields represented by snapshot v1, overlays them on a copy, and invokes the
same semantic comparison. Upserts are full-object replacements within this
security-relevant model. Deletion requires the explicit
`rbacviz.io/simulate-operation: delete` annotation. Unsupported kinds and
malformed objects fail closed; no manifest is partially accepted after an
error. Secret payload maps are never copied into a domain type or output.

There is deliberately no Kubernetes client or apply interface in the simulate
package. The CLI requires a saved snapshot and never falls back to collection.
This layer measures user-supplied proposals. The remediation engine reuses the
same semantic comparison for every generated candidate.

## Minimal remediation algorithm

1. Select dangerous paths in scope and identify mutable cut points backed by
   user-controlled Kubernetes configuration.
2. Generate structured candidates: remove a subject grant, narrow a rule,
   replace cluster binding scope, change a workload identity, disable token
   automount, or add a supported control.
3. Clone the immutable snapshot through copy-on-write overlay.
4. Apply one candidate virtually and validate the resulting snapshot.
5. Recompute only invalidated grants, graph regions, findings, and paths; the
   first implementation may safely recompute everything for correctness.
6. Measure removed and remaining path IDs, risk delta, lost capabilities,
   affected identities, and unresolved redundant grants.
7. Rank by security benefit, confidence, permission preservation, operational
   cost, and stable candidate ID.

A candidate is never recommended solely because it touches a dangerous edge.
It must be simulated and show measurable impact. No MVP remediation writes to
the cluster.

### Ranking

```text
benefit = removedCritical*largeWeight
        + removedHigh*mediumWeight
        + totalRiskReduction
        + blastRadiusReduction

cost = permissionLoss
     + affectedIdentityCount
     + operationalComplexity
     + uncertaintyPenalty
```

Candidates are Pareto-filtered before a deterministic benefit-to-cost ranking.
The output always includes both benefit and estimated operational impact so the
user can make the final decision.

### Remediation model 1.0.0

The delivered model generates only changes that the snapshot schema and
analysis engines can evaluate without inventing runtime semantics:

- remove one exact subject from one exact RoleBinding or ClusterRoleBinding;
- remove one explicit non-wildcard verb from the exact source policy rule;
- set the observed namespace Pod Security Admission enforce level to
  `restricted` for a modeled host-escape path.

Each action is applied to a deep canonical clone. Empty bindings and rules are
removed from the simulated representation, identities are re-derived, and the
same semantic diff performs complete permission, finding, attack-path, control,
and risk analysis. The input and every other candidate remain immutable.

Version `1.0.0` uses explicit integer components:

```text
benefit = removedCriticalPaths*1200
        + removedHighPaths*700
        + removedMediumPaths*300
        + newlyBlockedPaths*900
        + clusterRiskReduction*20
        + scopedRiskReduction*5

cost = lostCapabilities*100
     + affectedIdentities*200
     + operationalComplexity*100
     + uncertaintyPenalty

ratioBasisPoints = benefit*10000 / max(cost, 100)
```

Operational complexity is 2 for exact subject removal, 3 for rule narrowing,
and 4 for PSA enforcement. Incomplete collection or a truncated derived
analysis adds 500 cost points and keeps the whole result incomplete. A
candidate is Pareto-dominated when another measured candidate has at least its
benefit and no greater cost, with one strict inequality. Remaining ties use
ratio, benefit, cost, and stable candidate ID as a total order.

`RECOMMENDED` means measurable and Pareto-optimal, `DOMINATED` means measurable
but inferior within the generated set, and `INEFFECTIVE` means no modeled path
or risk reduction. Provenance-only removal of one redundant grant is therefore
retained as evidence but never presented as successful remediation.
