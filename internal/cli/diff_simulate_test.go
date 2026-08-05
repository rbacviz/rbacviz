package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	semanticdiff "github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/simulate"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestDiffCommandOfflineHumanAndJSON(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	beforePath := filepath.Join(directory, "before.json")
	afterPath := filepath.Join(directory, "after.json")
	before := cliDiffSnapshot()
	after := cliDiffSnapshot()
	after.Roles = append(after.Roles, snapshot.Role{
		Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "danger"},
		Rules: []snapshot.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
	})
	after.Bindings = append(after.Bindings, snapshot.Binding{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "danger"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "danger"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	})
	if err := snapshot.Save(beforePath, before); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Save(afterPath, after); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := execute("diff", beforePath, afterPath)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "semantic snapshot diff") || !strings.Contains(stdout, "dangerous ADDED") {
		t.Fatalf("diff code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = execute("diff", beforePath, afterPath, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("diff JSON code=%d stderr=%q", code, stderr)
	}
	var result semanticdiff.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "1.0" || result.Summary.DangerousCapabilitiesNew == 0 || result.Risk.Cluster.Delta <= 0 {
		t.Fatalf("diff result = %+v", result.Summary)
	}
}

func TestSimulateCommandIsOfflineAndSupportsSnapshotShorthand(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "cluster.json")
	manifestPath := filepath.Join(directory, "proposed.yaml")
	if err := snapshot.Save(snapshotPath, cliDiffSnapshot()); err != nil {
		t.Fatal(err)
	}
	manifest := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: token-minter
rules:
- apiGroups: [""]
  resources: ["serviceaccounts/token"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: token-minter
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: token-minter
subjects:
- kind: User
  name: alice
`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute("simulate", "-s", snapshotPath, "-f", manifestPath, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("simulate code=%d stderr=%q", code, stderr)
	}
	var result simulate.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Applied) != 2 || result.Diff.Summary.PermissionsAdded == 0 || result.Diff.Summary.AttackPathsAdded == 0 {
		t.Fatalf("simulation result = %+v", result.Diff.Summary)
	}
}

func TestSimulateNeverFallsBackToLiveCollection(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "role.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := execute("simulate", "-f", path)
	if code != 2 || !strings.Contains(stderr, "never falls back to a live cluster") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func cliDiffSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true},
		},
		Roles: []snapshot.Role{{
			Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
			Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		}},
		Bindings: []snapshot.Binding{{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "readers"},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
		}},
	}
}
