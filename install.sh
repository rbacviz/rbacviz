#!/bin/sh

set -eu

repository="rbacviz/rbacviz"
install_dir="${RBACVIZ_INSTALL_DIR:-${HOME}/.local/bin}"
requested_version="${RBACVIZ_VERSION:-latest}"

fail() {
	printf 'rbacviz installer: %s\n' "$*" >&2
	exit 1
}

require() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require curl
require tar
require mktemp

case "$(uname -s)" in
	Linux) os="linux" ;;
	Darwin) os="darwin" ;;
	*) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) fail "unsupported architecture: $(uname -m)" ;;
esac

case "$requested_version" in
	latest) release_path="latest/download" ;;
	v[0-9]*.[0-9]*.[0-9]*) release_path="download/$requested_version" ;;
	*) fail "RBACVIZ_VERSION must be 'latest' or a tag such as v0.1.0" ;;
esac

release_url="https://github.com/${repository}/releases/${release_path}"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

checksums="$temporary_dir/checksums.txt"
curl -fL --proto '=https' --tlsv1.2 --retry 3 --output "$checksums" \
	"$release_url/checksums.txt"

suffix="_${os}_${arch}.tar.gz"
match="$(awk -v suffix="$suffix" '
	length($1) == 64 && substr($2, length($2) - length(suffix) + 1) == suffix {
		print $1 " " $2
	}
' "$checksums")"

set -- $match
[ "$#" -eq 2 ] || fail "expected exactly one checksum for ${os}/${arch}"
expected_checksum="$1"
archive_name="$2"

case "$archive_name" in
	rbacviz_*"$suffix") ;;
	*) fail "release contains an unexpected archive name: $archive_name" ;;
esac

archive="$temporary_dir/$archive_name"
curl -fL --proto '=https' --tlsv1.2 --retry 3 --output "$archive" \
	"$release_url/$archive_name"

if command -v sha256sum >/dev/null 2>&1; then
	actual_checksum="$(sha256sum "$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
	actual_checksum="$(shasum -a 256 "$archive" | awk '{print $1}')"
else
	fail "sha256sum or shasum is required to verify the download"
fi

[ "$actual_checksum" = "$expected_checksum" ] || fail "SHA-256 verification failed"

archive_root="${archive_name%.tar.gz}"
tar -xzf "$archive" -C "$temporary_dir"
binary="$temporary_dir/$archive_root/rbacviz"
[ -f "$binary" ] || fail "verified archive does not contain rbacviz"

mkdir -p "$install_dir"
destination="$install_dir/rbacviz"
staged="$install_dir/.rbacviz.install.$$"
trap 'rm -rf "$temporary_dir"; rm -f "$staged"' EXIT HUP INT TERM
cp "$binary" "$staged"
chmod 0755 "$staged"
mv "$staged" "$destination"

printf 'Installed rbacviz to %s\n' "$destination"
case ":${PATH}:" in
	*":${install_dir}:"*) ;;
	*) printf 'Add %s to PATH, then run: rbacviz version\n' "$install_dir" ;;
esac

