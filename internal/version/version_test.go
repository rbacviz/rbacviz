package version_test

import (
	"bytes"
	"testing"

	"github.com/rbacviz/rbacviz/internal/version"
)

func TestWriteHuman(t *testing.T) {
	t.Parallel()

	info := version.Info{Version: "v0.1.0", Commit: "abc123", BuildDate: "2026-08-05T12:00:00Z", Dirty: true, GoVersion: "go1.24.0", Platform: "linux/amd64"}
	var output bytes.Buffer
	if err := version.Write(&output, "human", info); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	want := "rbacviz v0.1.0\ncommit: abc123 (dirty)\nbuilt: 2026-08-05T12:00:00Z\ngo: go1.24.0\nplatform: linux/amd64\n"
	if got := output.String(); got != want {
		t.Fatalf("Write() = %q, want %q", got, want)
	}
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	info := version.Info{Version: "dev", Commit: "none", BuildDate: "unknown", GoVersion: "go1.24.0", Platform: "darwin/arm64"}
	var output bytes.Buffer
	if err := version.Write(&output, "json", info); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	want := "{\n  \"version\": \"dev\",\n  \"commit\": \"none\",\n  \"buildDate\": \"unknown\",\n  \"dirty\": false,\n  \"goVersion\": \"go1.24.0\",\n  \"platform\": \"darwin/arm64\"\n}\n"
	if got := output.String(); got != want {
		t.Fatalf("Write() = %q, want %q", got, want)
	}
}
