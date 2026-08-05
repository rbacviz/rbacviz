# Offline example clusters

These snapshots are synthetic, credential-free fixtures. They contain no real
cluster identifiers or Secret values.

| Snapshot | Purpose |
| --- | --- |
| `token-minter.json` | namespaced ServiceAccount token creation and a high-risk identity |
| `host-escape-blocked.json` | Pod creation whose host-escape path is blocked by observed PSA `restricted` |
| `partial-collection.json` | a positive finding plus an explicit collection gap and incomplete confidence |

Try them without a Kubernetes connection:

```bash
rbacviz findings --snapshot examples/clusters/token-minter.json
rbacviz attack-path --snapshot examples/clusters/host-escape-blocked.json
rbacviz risk --snapshot examples/clusters/partial-collection.json
rbacviz tui --snapshot examples/clusters/token-minter.json
```

The examples demonstrate analysis semantics, not exploitation. No command
executes a path or changes a cluster.
