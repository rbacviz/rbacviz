package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/cli"
	"github.com/rbacviz/rbacviz/internal/config"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/snapshot"
	"github.com/rbacviz/rbacviz/internal/version"
)

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := execute("version")
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr = %s", code, stderr)
	}
	want := "rbacviz v0.1.0\ncommit: abc123\nbuilt: 2026-08-05T12:00:00Z\ngo: go1.24.0\nplatform: linux/amd64\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := execute("version", "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"version": "v0.1.0"`) {
		t.Fatalf("stdout does not contain version JSON: %s", stdout)
	}
}

func TestUnknownFlagUsesExitCodeTwo(t *testing.T) {
	t.Parallel()

	code, _, stderr := execute("version", "--not-a-flag")
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown flag") {
		t.Fatalf("stderr = %q, want unknown flag", stderr)
	}
}

func TestConfigRejectsSourceConflict(t *testing.T) {
	t.Parallel()

	code, _, stderr := execute("config", "--snapshot", "cluster.json", "--context", "production")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "cannot be combined") {
		t.Fatalf("stderr = %q, want conflict explanation", stderr)
	}
}

func TestRootHelpHasNoFuturePlaceholders(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := execute("--help")
	if code != 0 || stderr != "" {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "version") || !strings.Contains(stdout, "config") || !strings.Contains(stdout, "snapshot") || !strings.Contains(stdout, "permissions") || !strings.Contains(stdout, "who-can") || !strings.Contains(stdout, "why-can") || !strings.Contains(stdout, "graph") || !strings.Contains(stdout, "findings") || !strings.Contains(stdout, "explain") || !strings.Contains(stdout, "attack-path") || !strings.Contains(stdout, "risk") || !strings.Contains(stdout, "tui") || !strings.Contains(stdout, "diff") || !strings.Contains(stdout, "simulate") {
		t.Fatalf("help is missing implemented commands: %s", stdout)
	}
	if strings.Contains(stdout, "\n  scan ") {
		t.Fatalf("help contains unimplemented command: %s", stdout)
	}
}

func TestFindingsJSONSARIFAndExplainFromOfflineSnapshot(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "findings.json")
	value := snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata:     snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true}},
		Roles: []snapshot.Role{{
			Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "secret-reader"},
			Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}}},
		}},
		Bindings: []snapshot.Binding{{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "secret-reader"},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "secret-reader"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
		}},
	}
	if err := snapshot.Save(path, value); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute("findings", "--severity", "high", "--namespace", "prod", "--snapshot", path, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("findings code = %d stderr = %q", code, stderr)
	}
	var result struct {
		Findings []struct {
			ID     string `json:"id"`
			RuleID string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil || len(result.Findings) != 1 || result.Findings[0].RuleID != "RBACVIZ-R007" {
		t.Fatalf("findings output = %q error = %v", stdout, err)
	}
	code, stdout, stderr = execute("explain", result.Findings[0].ID, "--snapshot", path)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "grant:") || !strings.Contains(stdout, "recommendation:") {
		t.Fatalf("explain code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
	code, stdout, stderr = execute("findings", "--snapshot", path, "--output", "sarif")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"version": "2.1.0"`) || !strings.Contains(stdout, `"ruleId": "RBACVIZ-R007"`) {
		t.Fatalf("SARIF code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
}

func TestSARIFRejectedByUnsupportedCommand(t *testing.T) {
	t.Parallel()
	code, _, stderr := execute("version", "--output", "sarif")
	if code != 1 || !strings.Contains(stderr, "supported by findings and explain") {
		t.Fatalf("code = %d stderr = %q", code, stderr)
	}
}

func TestTUIRejectsMachineOutputBeforeStartingProgram(t *testing.T) {
	t.Parallel()
	code, _, stderr := execute("tui", "--output", "json")
	if code != 2 || !strings.Contains(stderr, "requires --output human") {
		t.Fatalf("code = %d stderr = %q", code, stderr)
	}
}

func TestPermissionCommandsFromOfflineSnapshot(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "permissions.json")
	value := snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata:     snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}}},
		Roles: []snapshot.Role{{
			Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
			Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		}},
		Bindings: []snapshot.Binding{{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "readers"},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, APIGroup: "rbac.authorization.k8s.io", Name: "alice"}},
		}},
	}
	if err := snapshot.Save(path, value); err != nil {
		t.Fatalf("snapshot.Save() error = %v", err)
	}

	code, stdout, stderr := execute("permissions", "user:alice", "--snapshot", path, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("permissions code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"schemaVersion": "1.0"`) || !strings.Contains(stdout, `"bindingRef"`) || !strings.Contains(stdout, `"resource": "pods"`) {
		t.Fatalf("permissions JSON lacks contract fields: %s", stdout)
	}

	code, stdout, stderr = execute("why-can", "user:alice", "get", "pods", "--namespace", "prod", "--snapshot", path)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "allowed: true") || !strings.Contains(stdout, "RoleBinding prod/readers") {
		t.Fatalf("why-can code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	code, stdout, stderr = execute("who-can", "get", "pods", "--namespace", "prod", "--snapshot", path)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "user:alice") {
		t.Fatalf("who-can code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	code, stdout, stderr = execute("graph", "stats", "--snapshot", path, "--output", "json")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"RESOURCE_SELECTOR"`) || !strings.Contains(stdout, `"BOUND_BY"`) {
		t.Fatalf("graph stats code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	code, stdout, stderr = execute("graph", "nodes", "--type", "RESOURCE_SELECTOR", "--name", "pods", "--node-namespace", "prod", "--snapshot", path, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("graph nodes code = %d, stderr = %q", code, stderr)
	}
	var listed struct {
		Nodes []graphmodel.Node `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil || len(listed.Nodes) != 1 {
		t.Fatalf("graph nodes output = %q, error = %v", stdout, err)
	}
	code, stdout, stderr = execute("graph", "paths", "--from", "identity:user:alice", "--to", listed.Nodes[0].Key, "--snapshot", path, "--output", "json")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"relation": "ALLOWS"`) || !strings.Contains(stdout, `"relation": "REACHES"`) {
		t.Fatalf("graph paths code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestPermissionCommandsRejectInvalidIdentity(t *testing.T) {
	t.Parallel()
	code, _, stderr := execute("permissions", "alice")
	if code != 2 || !strings.Contains(stderr, "identity must be") {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestSnapshotSaveAndInspect(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cluster.json")
	collector := func(context.Context, config.Config, string) (snapshot.Snapshot, error) {
		return snapshot.Snapshot{
			SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
			Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", Complete: true},
			Roles:    []snapshot.Role{{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "reader"}}},
		}, nil
	}
	code, stdout, stderr := executeWithCollector(collector, "snapshot", "save", "--file", path)
	if code != 0 || stderr != "" {
		t.Fatalf("save code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "roles: 1") {
		t.Fatalf("save stdout = %q", stdout)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot was not saved: %v", err)
	}
	code, stdout, stderr = execute("snapshot", "inspect", path, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("inspect code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"schemaVersion": "1.0"`) || !strings.Contains(stdout, `"roles": 1`) {
		t.Fatalf("inspect stdout = %q", stdout)
	}
}

func TestSnapshotStrictUsesExitCodeThreeAndDoesNotWrite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "partial.json")
	collector := func(context.Context, config.Config, string) (snapshot.Snapshot, error) {
		return snapshot.Snapshot{
			SchemaVersion: snapshot.SchemaVersion,
			Metadata:      snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z"},
			Warnings:      []snapshot.Warning{{Resource: "roles", Code: "Forbidden", Message: "roles collection failed (Forbidden)"}},
		}, nil
	}
	code, _, stderr := executeWithCollector(collector, "snapshot", "save", "--strict", "--file", path)
	if code != 3 {
		t.Fatalf("code = %d, want 3; stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "incomplete") {
		t.Fatalf("stderr = %q", stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial snapshot exists or stat failed unexpectedly: %v", err)
	}
}

func execute(args ...string) (int, string, string) {
	return executeWithCollector(nil, args...)
}

func executeWithCollector(collector func(context.Context, config.Config, string) (snapshot.Snapshot, error), args ...string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := cli.Execute(context.Background(), args, cli.IOStreams{
		In: strings.NewReader(""), Out: &stdout, ErrOut: &stderr,
	}, cli.Dependencies{
		Version: version.Info{
			Version: "v0.1.0", Commit: "abc123", BuildDate: "2026-08-05T12:00:00Z",
			GoVersion: "go1.24.0", Platform: "linux/amd64",
		},
		LookupEnv:       func(string) (string, bool) { return "", false },
		UserConfigDir:   func() (string, error) { return "/path/that/does/not/exist", nil },
		CollectSnapshot: collector,
	})
	return code, stdout.String(), stderr.String()
}
