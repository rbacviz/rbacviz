#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION COMMIT SOURCE_DATE_EPOCH" >&2
  exit 2
fi

version="$1"
commit="$2"
source_date_epoch="$3"
first="$(mktemp -d "${TMPDIR:-/tmp}/rbacviz-repro-first.XXXXXX")"
second="$(mktemp -d "${TMPDIR:-/tmp}/rbacviz-repro-second.XXXXXX")"
cleanup() {
  rm -rf "$first" "$second"
}
trap cleanup EXIT HUP INT TERM

go run ./hack/release \
  --version "$version" --commit "$commit" \
  --source-date-epoch "$source_date_epoch" --output "$first" >/dev/null
go run ./hack/release \
  --version "$version" --commit "$commit" \
  --source-date-epoch "$source_date_epoch" --output "$second" >/dev/null

diff -qr "$first" "$second"
echo "release artifacts are byte-for-byte reproducible"
