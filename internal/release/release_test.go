package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestArchivesAreDeterministicAndNormalized(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "rbacviz")
	if err := os.WriteFile(input, []byte("binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []File{{Name: "rbacviz", Path: input, Mode: 0o755}}
	epoch := time.Unix(1_700_000_000, 0).UTC()
	firstTar, secondTar := filepath.Join(directory, "first.tar.gz"), filepath.Join(directory, "second.tar.gz")
	if err := TarGz(firstTar, "rbacviz_1.0.0_linux_amd64", epoch, files); err != nil {
		t.Fatal(err)
	}
	if err := TarGz(secondTar, "rbacviz_1.0.0_linux_amd64", epoch, files); err != nil {
		t.Fatal(err)
	}
	assertSameFile(t, firstTar, secondTar)
	// #nosec G304 -- the test owns this temporary path.
	inputTar, err := os.Open(firstTar)
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(inputTar)
	if err != nil {
		t.Fatal(err)
	}
	header, err := tar.NewReader(gzipReader).Next()
	if err != nil {
		t.Fatal(err)
	}
	if header.Uid != 0 || header.Gid != 0 || header.ModTime.Unix() != epoch.Unix() || header.Mode != 0o755 {
		t.Fatalf("non-normalized tar header: %+v", header)
	}

	firstZip, secondZip := filepath.Join(directory, "first.zip"), filepath.Join(directory, "second.zip")
	if err := Zip(firstZip, "rbacviz_1.0.0_windows_amd64", epoch, files); err != nil {
		t.Fatal(err)
	}
	if err := Zip(secondZip, "rbacviz_1.0.0_windows_amd64", epoch, files); err != nil {
		t.Fatal(err)
	}
	assertSameFile(t, firstZip, secondZip)
	zipReader, err := zip.OpenReader(firstZip)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zipReader.Close() }()
	if len(zipReader.File) != 1 || zipReader.File[0].Mode().Perm() != 0o755 {
		t.Fatalf("non-normalized zip: %+v", zipReader.File)
	}
}

func TestCycloneDXIsStableAndExcludesMainFromDependencies(t *testing.T) {
	modules := []Module{{Path: "github.com/rbacviz/rbacviz", Main: true}, {Path: "example.com/z", Version: "v1.0.0"}, {Path: "example.com/a", Version: "v2.0.0"}}
	first, err := CycloneDX("github.com/rbacviz/rbacviz", "v0.1.0", "2026-08-05T00:00:00Z", modules)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := CycloneDX("github.com/rbacviz/rbacviz", "v0.1.0", "2026-08-05T00:00:00Z", modules)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("SBOM is not stable")
	}
	var value map[string]any
	if err := json.Unmarshal(first, &value); err != nil {
		t.Fatal(err)
	}
	components := value["components"].([]any)
	if len(components) != 2 || !strings.Contains(string(first), "example.com/a") {
		t.Fatalf("unexpected SBOM: %s", first)
	}
}

func TestChecksumsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checksums.txt")
	values := []Digest{{Name: "b.zip", SHA256: strings.Repeat("b", 64)}, {Name: "a.tar.gz", SHA256: strings.Repeat("a", 64)}}
	if err := WriteChecksums(path, values); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- the test owns this temporary path.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadChecksums(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed["a.tar.gz"] != strings.Repeat("a", 64) || !strings.HasPrefix(string(data), strings.Repeat("a", 64)) {
		t.Fatalf("unexpected checksums: %q", data)
	}
}

func TestReleaseRejectsNonemptyOutput(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "stale.zip"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireEmptyOutput(directory); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("expected stale output rejection, got %v", err)
	}
}

func assertSameFile(t *testing.T, left, right string) {
	t.Helper()
	// #nosec G304 -- the test owns both temporary paths.
	first, err := os.ReadFile(left)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- the test owns both temporary paths.
	second, err := os.ReadFile(right)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("files differ")
	}
}
