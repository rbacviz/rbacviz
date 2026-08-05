# Release process

`rbacviz` releases are built from one source tree with one Go toolchain. The
release helper compiles five static binaries, places each in a platform archive,
emits a CycloneDX 1.5 SBOM and release manifest, and writes SHA-256 checksums.

## Supported artifacts

| Target | Archive |
| --- | --- |
| Linux amd64 | `rbacviz_<version>_linux_amd64.tar.gz` |
| Linux arm64 | `rbacviz_<version>_linux_arm64.tar.gz` |
| macOS amd64 | `rbacviz_<version>_darwin_amd64.tar.gz` |
| macOS arm64 | `rbacviz_<version>_darwin_arm64.tar.gz` |
| Windows amd64 | `rbacviz_<version>_windows_amd64.zip` |

Every archive contains the binary, `LICENSE`, `README.md`, and `SECURITY.md` in
a versioned top-level directory. `checksums.txt`, the SBOM, and the manifest are
published beside the archives.

## Local release

Use a clean source tree and Go 1.25.12, the patched toolchain pinned by the
initial `v0.1.x` release workflow:

```bash
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
make verify lint vuln
make verify-reproducible \
  VERSION=v0.1.0 COMMIT="$(git rev-parse HEAD)" \
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
make release \
  VERSION=v0.1.0 COMMIT="$(git rev-parse HEAD)" \
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
```

Release metadata is injected through the linker. Builds use `CGO_ENABLED=0`,
`-trimpath`, `-buildvcs=false`, and an empty Go build ID. Archive order, modes,
owners, and timestamps are normalized to `SOURCE_DATE_EPOCH`.

The selected output directory must be empty. Release generation fails closed
when it finds any existing file, preventing stale or partially written artifacts
from being published with a new tag.

The reproducibility check builds twice in independent temporary directories and
requires every output byte to match. Reproducibility assumes the same source,
Go toolchain, module graph, environment architecture, and release helper.

## Verification by consumers

```bash
sha256sum -c checksums.txt
tar -xzf rbacviz_0.1.0_linux_amd64.tar.gz
./rbacviz_0.1.0_linux_amd64/rbacviz version --output json
```

On macOS use `shasum -a 256`; on Windows use `Get-FileHash -Algorithm SHA256`.
The version command should show the published version, commit, deterministic
build timestamp, `dirty: false`, Go version, and target platform.

## SBOM scope

The CycloneDX document inventories the main Go module and resolved module build
list used by `go list -m -json all`. It does not claim to inventory the host OS,
CI runner, kubeconfig plugins, or Kubernetes cluster components.

## CI publication

The release workflow runs on `v*` tags. It verifies tests, vet, formatting,
lint, vulnerability analysis, generated screenshots, byte reproducibility, and
checksums before publishing. The workflow requests read-only repository access
except for the final GitHub release and build-provenance attestation steps.

A failed check stops publication; releases are never assembled from previous
`dist` contents.
