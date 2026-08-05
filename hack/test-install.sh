#!/bin/sh

set -eu

repository_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

fixture_dir="$test_dir/fixtures"
archive_root="rbacviz_0.1.0_linux_amd64"
mkdir -p "$fixture_dir/$archive_root" "$test_dir/fake-bin" "$test_dir/install"

printf '#!/bin/sh\nprintf "rbacviz test binary\\n"\n' > "$fixture_dir/$archive_root/rbacviz"
chmod 0755 "$fixture_dir/$archive_root/rbacviz"
tar -czf "$fixture_dir/${archive_root}.tar.gz" -C "$fixture_dir" "$archive_root"
checksum="$(sha256sum "$fixture_dir/${archive_root}.tar.gz" | awk '{print $1}')"
printf '%s  %s\n' "$checksum" "${archive_root}.tar.gz" > "$fixture_dir/checksums.txt"

cat > "$test_dir/fake-bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=""
url=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		--output) output="$2"; shift 2 ;;
		-*) shift ;;
		*) url="$1"; shift ;;
	esac
done
cp "$RBACVIZ_TEST_FIXTURES/${url##*/}" "$output"
EOF
chmod 0755 "$test_dir/fake-bin/curl"

PATH="$test_dir/fake-bin:$PATH" \
	RBACVIZ_TEST_FIXTURES="$fixture_dir" \
	RBACVIZ_INSTALL_DIR="$test_dir/install" \
	sh "$repository_dir/install.sh" >/dev/null

test -x "$test_dir/install/rbacviz"
test "$("$test_dir/install/rbacviz")" = "rbacviz test binary"

printf 'installer test passed\n'

