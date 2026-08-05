# Permission resolution

## Goal and boundary

The resolver calculates permissions implied by collected Kubernetes RBAC
objects. It does not claim to reproduce every API-server authorization mode.
Optional SubjectAccessReview verification may later annotate a specific query,
but it never replaces deterministic offline calculation.

## Inputs and indexes

Build immutable indexes from a validated snapshot:

- Role by `(namespace, name)`;
- ClusterRole by `name`;
- bindings by canonical subject key;
- API resource scope by `(apiGroup, resource)`;
- ClusterRole aggregation dependencies and reverse dependencies.

Invalid role references produce structured warnings and no phantom grant.

## Aggregated ClusterRoles

1. Parse every ClusterRole aggregation selector.
2. Select matching ClusterRoles using Kubernetes label-selector semantics.
3. Build the aggregation dependency graph.
4. Compute a fixed point of included policy rules.
5. Deduplicate rules by canonical rule ID while retaining every aggregation
   provenance chain.
6. Detect cycles and terminate deterministically; cycles become warnings and
   do not duplicate rules indefinitely.

Aggregation is calculated from snapshot content, not from an assumption that
the control plane has already materialized all aggregate rules.

## Binding resolution

For an identity query:

1. obtain all RoleBindings and ClusterRoleBindings whose subjects match the
   canonical identity;
2. resolve each `roleRef` exactly;
3. assign binding scope:
   - RoleBinding grants only in its namespace, even when it references a
     ClusterRole;
   - ClusterRoleBinding grants cluster-wide, with namespaced resources valid
     in all namespaces;
4. normalize every policy rule into matchable capability selectors;
5. attach grant evidence containing the subject, binding, role, rule, and
   aggregation chain;
6. coalesce equal capabilities while preserving all grants;
7. sort results by scope, namespace, API group, resource, subresource, verb,
   names, then evidence key.

Group membership cannot be discovered from Kubernetes RBAC alone. A query for
a User therefore includes direct User subjects plus explicitly supplied groups;
the tool must not invent group membership.

## Matching algorithm

Resource request matching evaluates all of the following:

- exact verb or `*`;
- exact API group or `*`;
- exact resource, `*`, or exact `resource/subresource`;
- namespace compatibility with binding scope and discovered API resource
  scope;
- `resourceNames` compatibility when a request names an object;
- no match for an unnamed collection request when a rule is restricted by
  `resourceNames`;
- resource rules and non-resource URL rules through separate matchers.

Non-resource URLs support exact paths and Kubernetes' documented trailing `*`
prefix form. They never match resource requests.

Unknown discovery information remains matchable but lowers certainty for scope
dependent queries; it is not silently treated as namespaced or cluster-scoped.

## Query behavior

### `permissions identity`

Returns all normalized capabilities and every grant path.

### `who-can verb resource`

Resolves bindings once, evaluates capabilities against the requested action,
and returns identities grouped by canonical key with matching evidence.

### `why-can identity verb resource`

Returns every independent grant, not just the first. This matters because a
remediation that removes one redundant binding may not remove the permission.

## Complexity and caching

Resolution avoids identity-by-rule full scans after index construction.
Memoized results are keyed by canonical snapshot digest, identity key, supplied
group set, and resolver options. Caches are deterministic and bounded; they are
discarded when the snapshot changes.

## Required Milestone 3 tests

- RoleBinding to Role and ClusterRole;
- ClusterRoleBinding scope;
- wildcard verbs/groups/resources;
- `resourceNames` with named and unnamed requests;
- subresources;
- non-resource URLs;
- duplicate and independent grants;
- aggregation chains and cycles;
- missing role references;
- unknown API discovery scope;
- deterministic ordering.

