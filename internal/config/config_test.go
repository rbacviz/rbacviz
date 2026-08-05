package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rbacviz/rbacviz/internal/config"
)

func TestLoadPrecedence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"namespace":"from-file","output":"json","timeout":"45s","noColor":true}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	environment := map[string]string{
		"RBACVIZ_NAMESPACE": "from-env",
		"RBACVIZ_TIMEOUT":   "1m",
	}
	flagNamespace := "from-flag"
	result, err := config.Load(config.LoadOptions{
		FilePath:     path,
		FileRequired: true,
		LookupEnv: func(key string) (string, bool) {
			value, ok := environment[key]
			return value, ok
		},
		Overrides: config.Overrides{Namespace: &flagNamespace},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := result.Config.Namespace; got != "from-flag" {
		t.Fatalf("Namespace = %q, want from-flag", got)
	}
	if got := result.Config.Timeout; got != time.Minute {
		t.Fatalf("Timeout = %s, want 1m", got)
	}
	if got := result.Config.Output; got != "json" {
		t.Fatalf("Output = %q, want json", got)
	}
	if !result.Config.NoColor {
		t.Fatal("NoColor = false, want true")
	}
	if got := result.Sources["namespace"]; got != config.SourceFlag {
		t.Fatalf("namespace source = %q, want flag", got)
	}
	if got := result.Sources["timeout"]; got != config.SourceEnv {
		t.Fatalf("timeout source = %q, want environment", got)
	}
	if got := result.Sources["output"]; got != config.SourceFile {
		t.Fatalf("output source = %q, want file", got)
	}
}

func TestLoadRejectsUnknownFileField(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"mystery":true}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := config.Load(config.LoadOptions{FilePath: path, FileRequired: true})
	if err == nil {
		t.Fatal("Load() error = nil, want unknown-field error")
	}
}

func TestValidateConflictingSources(t *testing.T) {
	t.Parallel()

	err := config.Validate(config.Config{
		Snapshot: "cluster.json",
		Context:  "production",
		Output:   config.DefaultOutput,
		LogLevel: config.DefaultLogLevel,
		Timeout:  config.DefaultTimeout,
	})
	if err == nil {
		t.Fatal("Validate() error = nil, want source conflict")
	}
}
