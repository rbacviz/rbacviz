# Changelog

All notable changes to `rbacviz` are documented in this file. The project uses
Semantic Versioning.

## [0.2.0] - 2026-08-16

### Added

- Root-cause-oriented `rbacviz report` output in Markdown, versioned JSON, and
  SARIF 2.1.0.
- Evidence-backed Access Chains from workload and identity through binding and
  role to effective permissions, shared by reports and the responsive TUI.
- A fourth adaptive TUI panel for access provenance and analytical guidance.
- Reviewed YAML/JSON baselines with exact selectors, mandatory owner/reason/
  expiry metadata, and auditable `ACCEPTED`, `EXPIRED`, and `UNMATCHED` states.
- SARIF root-cause fingerprints, Kubernetes object locations, analysis
  notifications, and safe mapping of fully accepted exceptions.

### Changed

- Risk Index model `2.0.0` groups derivative paths into binding/subject risk
  families, bounds diversity contributions, and avoids double-counting
  semantically redundant grants.
- Reports now separate impact severity, confidence, actionability, remediation
  priority, and the posture-oriented Risk Index.
- Permission views count and display independent grants from canonical grant
  provenance instead of permission-node approximations.

### Security

- A narrow rule-only suppression cannot suppress an entire root-cause family
  or grouped SARIF result.
- Accepted signals retain findings, attack paths, Access Chains, and evidence;
  only explicitly accepted families are removed from the active posture rollup.
- Report files are written atomically with owner-only permissions, and all new
  report/SARIF paths remain offline and mutation-free.

## [0.1.0] - 2026-08-05

- Initial terminal-first Kubernetes RBAC analyzer with canonical snapshots,
  permission provenance, typed graphs, findings, attack paths, transparent risk
  scoring, TUI investigation, semantic diff, offline simulation, advisory
  remediation, deterministic releases, checksums, SBOM, and provenance.
