# Domain and snapshot model

## Glossary

| Term | Meaning |
| --- | --- |
| Identity | User, Group, or ServiceAccount that may receive authorization |
| Subject | Binding reference that resolves to an identity |
| Grant | Exact binding, role reference, and policy rule provenance for a capability |
| Capability | Normalized RBAC action over a resource or non-resource URL selector |
| Resource selector | API group, resource/subresource, optional names, scope, namespace |
| Finding | Rule-produced security observation with evidence and stable ID |
| Attack step | One evidence-backed transition between typed nodes |
| Attack path | Ordered steps ending at a typed privilege target |
| Mitigation observation | A control that may block or constrain a step |
| Confidence | `CONFIRMED`, `LIKELY`, `CONDITIONAL`, `BLOCKED`, or `UNKNOWN` |
| Snapshot | Versioned canonical input to all analysis |
| Overlay | Pure in-memory changes used by simulation or remediation |

## Core object references

All Kubernetes-backed objects use a normalized reference:

```text
ObjectRef
  apiGroup
  kind
  namespace
  name
  uid (optional provenance, excluded from portable semantic identity)
```

Portable stable IDs are hashes of a type discriminator and canonical semantic
key. A Role key, for example, is
`rbac.authorization.k8s.io|Role|namespace|name`. Collisions are treated as
validation errors rather than silently merged.

## Identity model

```text
Identity
  id
  kind: User | Group | ServiceAccount
  name
  namespace (ServiceAccount only)
  provenance[]
  labels{}
```

Users and Groups are discoveries, not Kubernetes API objects. Provenance lists
every binding or optional active-kubeconfig source that introduced them.

## Capability and grant model

Capabilities are normalized, typed, and separate from their grants:

```text
Capability
  apiGroup
  resource
  subresource
  verb
  resourceNames[]
  nonResourceURL
  scope: Namespaced | Cluster | NonResource
  namespace

GrantEvidence
  policyRuleID
  roleRef
  bindingRef
  subject
  originalRule
  aggregationChain[]
```

One capability can have multiple grants. This preserves explanations and lets
remediation estimate whether removing one binding actually removes access.
Wildcards remain explicit selectors and are not eagerly expanded across all
discovered objects.

## Graph model

The graph is a typed directed multigraph. Compact internal numeric IDs are an
implementation detail; every node and edge also has a stable portable ID.

### Node types

| Category | Types |
| --- | --- |
| Identity | `IDENTITY`, `SERVICE_ACCOUNT` |
| RBAC | `BINDING`, `ROLE`, `CLUSTER_ROLE`, `CAPABILITY`, `RESOURCE_SELECTOR` |
| Workload | `WORKLOAD`, `POD` |
| Asset | `SECRET`, `NODE`, `PERSISTENT_VOLUME`, `NAMESPACE` |
| Security | `SECURITY_CONTROL`, `ATTACK_TECHNIQUE`, `PRIVILEGE_TARGET` |

`SERVICE_ACCOUNT` is identity-capable but remains a distinct type for queries.
Unknown/custom Kubernetes resources are represented by `RESOURCE_SELECTOR` or
a generic resource payload without losing group/resource/scope information.

### Edge types

`BOUND_BY`, `GRANTS`, `ALLOWS`, `RUNS_AS`, `OWNS`, `MOUNTS`, `REFERENCES`,
`EXPOSES`, `CAN_CREATE`, `CAN_PATCH`, `CAN_DELETE`, `CAN_BIND`, `CAN_ESCALATE`,
`CAN_IMPERSONATE`, `CAN_EXEC`, `CAN_ATTACH`, `CAN_PROXY`, `CAN_APPROVE`,
`CAN_ASSUME`, `ENABLES`, `BLOCKED_BY`, `MITIGATED_BY`, and `REACHES`.

Every edge stores:

```text
Edge
  id
  fromID
  toID
  relation
  evidence[]
  scope
  prerequisites[]
  confidence
  cost
  ruleID
```

Evidence is mandatory for security-relevant edges. Structural edges such as
ownership cite the source object's metadata and field path.

## Snapshot schema v1 proposal

```text
Snapshot
  schemaVersion
  toolVersion
  metadata
  apiResources[]
  identities[]
  roles[]
  bindings[]
  serviceAccounts[]
  workloads[]
  assets[]
  securityControls[]
  collectionWarnings[]
```

Metadata contains collection time, requested context name, an optional
non-secret cluster fingerprint, and completeness flags. It never contains
kubeconfig credentials or bearer tokens.

Snapshot RBAC rules preserve the original rule plus a stable normalized rule
ID. Workloads contain only security-relevant template, ownership, identity,
volume, image, and security-context metadata. Secret assets contain object
metadata and references only; `.data`, `.stringData`, and token contents are
forbidden by schema validation. The v1 collector deliberately leaves the
optional Secret type empty because Kubernetes' partial-metadata response does
not expose it and fetching the full object would also retrieve its payload.

## Canonicalization

Before serialization or analysis:

1. normalize API group and core-group representation;
2. sort/deduplicate set-like rule fields;
3. preserve semantically meaningful list order only where Kubernetes does;
4. sort objects by stable semantic key;
5. sort warnings by resource and error code;
6. validate references, scope, and forbidden sensitive fields;
7. compute stable IDs from canonical semantic input.

The serializer uses ordinary JSON with deterministic arrays. Object maps are
avoided in the persisted schema where key evolution would make diffs opaque.

## Compatibility

- Readers reject unknown major schema versions.
- Additive fields within a major version are tolerated.
- Migration is explicit and pure: `vN -> vN+1`.
- Analysis records the ruleset version separately from snapshot schema.
- A snapshot may be valid but incomplete; warnings and completeness flags
  propagate into confidence calculations.
