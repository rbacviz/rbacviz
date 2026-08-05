#!/usr/bin/env sh
set -eu

mkdir -p dist

build() {
  target_os="$1"
  target_arch="$2"
  extension="$3"
  output="dist/rbacviz_${target_os}_${target_arch}${extension}"
  printf 'building %s/%s\n' "$target_os" "$target_arch"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -buildvcs=false -trimpath -o "$output" ./cmd/rbacviz
}

build linux amd64 ""
build linux arm64 ""
build darwin amd64 ""
build darwin arm64 ""
build windows amd64 ".exe"
