# Snapshot schema v1

The snapshot is the only input boundary used by future permission, graph, and
security analysis. Live collection and offline loading both produce the same
canonical `Snapshot` value.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Wire-format version; readers accept compatible `1.x` documents |
| `toolVersion` | Build that created the file; excluded from semantic IDs |
| `metadata` | Collection time, non-secret context/scope, and completeness |
| `apiResources` | Preferred discovery resources, scope, kind, and supported verbs |
| `identities` | Users, Groups, and ServiceAccounts with discovery provenance |
| `roles` | Roles and ClusterRoles with original normalized rules and aggregation selectors |
| `bindings` | RoleBindings and ClusterRoleBindings with canonical subjects and role refs |
| `serviceAccounts` | ServiceAccount metadata and token-automount setting |
| `workloads` | Pod/controller identity, ownership, image, Secret/ConfigMap/projected/hostPath volume references, and security metadata |
| `assets` | Metadata-only Secrets, ConfigMaps, Nodes, storage, CSR, Ingress, and Service objects |
| `securityControls` | Observable PSA, admission, Kyverno, and Gatekeeper controls |
| `collectionWarnings` | Safe, deterministic records of inaccessible or failed resource groups |

All set-like arrays are sorted and deduplicated. Persisted labels and control
details use ordered `[{"key":"...","value":"..."}]` pairs rather than maps.
Stable IDs are SHA-256-derived from type discriminators and portable semantic
keys; UIDs and timestamps do not affect those IDs.

## Completeness

`metadata.complete` is true only when no collection warning exists. Collection
continues across independent API failures. The warning contains a resource,
Kubernetes status reason, and fixed safe message; raw server errors are not
persisted because they may contain endpoints or credential-adjacent details.

Later analysis must propagate incomplete discovery into confidence instead of
treating missing data as evidence that a permission, workload, or control does
not exist.

## Sensitive-data boundary

The schema has no field for Secret payloads, environment-variable values,
kubeconfig content, tokens, certificate private keys, or admission webhook CA
bundles. Secrets and other assets are collected through the partial metadata
API. Workload conversion selects only names, references, images, identity, and
security-context properties from full workload responses.

The loader recursively rejects object fields named `data`, `stringData`,
`bearerToken`, `tokenFile`, `clientKeyData`, `privateKey`, or
`privateKeyData`, including when an otherwise additive v1 field contains one.

## Compatibility and canonicalization

- Unknown schema majors are rejected.
- Additive fields in schema major v1 are ignored by older readers.
- Canonical JSON always uses arrays instead of `null` for collections.
- Files are written to a same-directory temporary file, synced, and atomically
  renamed with mode `0600`.
- The semantic digest excludes collection time, context name, cluster
  fingerprint, and tool build; it retains scope and completeness evidence.
- Snapshot size is bounded to 256 MiB during loading.

Pure migrations will be added when a future schema version requires a semantic
change rather than an additive field.
