package simulate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestLoadPathAndRunNeverPersistSecretData(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "proposed.yaml")
	content := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-reader
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
- kind: User
  name: alice
---
apiVersion: v1
kind: Secret
metadata:
  name: credential
  namespace: prod
type: Opaque
data:
  password: dG9wLXNlY3JldA==
stringData:
  token: never-report-me
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	manifests, err := LoadPath(path, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 3 {
		t.Fatalf("manifests = %d, want 3", len(manifests))
	}
	result, err := Run(context.Background(), simulationBase(), manifests, Options{Diff: diff.Options{MaxPaths: 1000, MaxExpanded: 10000}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "dG9wLXNlY3JldA") || strings.Contains(string(encoded), "never-report-me") || strings.Contains(string(encoded), "stringData") {
		t.Fatalf("simulation leaked Secret data: %s", encoded)
	}
	if result.Diff.Summary.PermissionsAdded == 0 || result.Diff.Summary.FindingsAdded == 0 {
		t.Fatalf("simulation did not measure access: %+v", result.Diff.Summary)
	}
}

func TestLoadPathDefaultsNamespaceAndSortsDirectory(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for name, body := range map[string]string{
		"b.yaml": "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: second\n",
		"a.yaml": "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: first\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	values, err := LoadPath(directory, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0].Ref.Name != "first" || values[1].Ref.Name != "second" {
		t.Fatalf("manifest order = %+v", values)
	}
	if values[0].Ref.Namespace != "prod" || values[1].Ref.Namespace != "prod" {
		t.Fatalf("default namespace not applied: %+v", values)
	}
}

func TestDeleteAnnotationRemovesBinding(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "delete.yaml")
	content := `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: readers
  namespace: prod
  annotations:
    rbacviz.io/simulate-operation: delete
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := LoadPath(path, "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), simulationBase(), values, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Applied) != 1 || !result.Applied[0].Existed || result.Applied[0].Operation != OperationDelete {
		t.Fatalf("applied = %+v", result.Applied)
	}
	if result.Diff.Summary.PermissionsRemoved == 0 {
		t.Fatalf("removed permission not measured: %+v", result.Diff.Summary)
	}
	if result.Diff.Summary.IdentitiesRemoved != 1 {
		t.Fatalf("removed binding subject remained stale: %+v", result.Diff.Summary)
	}
}

func TestLoadPathRejectsUnsupportedKind(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "unknown.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: example.io/v1\nkind: Widget\nmetadata:\n  name: one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPath(path, "")
	if err == nil || !strings.Contains(err.Error(), "unsupported manifest kind") {
		t.Fatalf("LoadPath() error = %v", err)
	}
}

func simulationBase() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
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
