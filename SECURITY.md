# Security policy

`rbacviz` is a defensive security analyzer. It must not read Kubernetes Secret
values, apply remediation, or execute discovered attack paths.

Please do not open a public issue for a vulnerability that could expose cluster
metadata, credentials, snapshot contents, or unsafe command execution. Until a
dedicated private reporting address is published, use GitHub's private security
advisory feature for the repository.

Reports should include the affected version, reproduction conditions, impact,
and any suggested mitigation. Never attach real kubeconfigs, tokens, Secret
values, or unredacted production snapshots.

## Supported versions

Before the first stable release, only the newest `v0.x` release receives
security fixes. After `v1.0.0`, the current minor line and the previous minor
line will receive fixes unless a release notice states otherwise.

## Response targets

Maintainers aim to acknowledge a complete report within three business days,
confirm severity or request more information within seven business days, and
publish a coordinated fix as soon as it is safe. These are targets, not a
service-level agreement.

## Scope

Credential leakage, unsafe Kubernetes API operations, parser denial of service,
terminal escape injection, analysis results that silently suppress known
incompleteness, and release-integrity failures are in scope. Incorrect findings
that depend on undocumented cluster behavior may be ordinary bugs unless they
cause a material security decision failure.

See the full [threat model](docs/security/threat-model.md) for trust boundaries,
explicit exclusions, and residual risk.
