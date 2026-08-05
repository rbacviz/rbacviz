package cli_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestRiskOfflineHumanAndJSONContracts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "risk.json")
	if err := snapshot.Save(path, riskCLISnapshot()); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := execute("risk", "--identity", "user:alice", "--namespace", "prod", "--snapshot", path, "--output", "json", "--include-paths")
	if code != 0 || stderr != "" {
		t.Fatalf("code = %d stderr = %q", code, stderr)
	}
	var result risk.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if result.ModelVersion != risk.ModelVersion || len(result.PathScores) != 1 || result.PathScores[0].Formula.Numerator == 0 || result.PathScores[0].Path == nil {
		t.Fatalf("unexpected machine contract: %#v", result)
	}
	if result.Cluster.Score == 0 || len(result.Identities) != 1 || len(result.Namespaces) != 1 {
		t.Fatalf("aggregate contract is incomplete: %#v", result)
	}

	code, stdout, stderr = execute("risk", "--snapshot", path, "--top", "3")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "cluster risk:") || !strings.Contains(stdout, "factor: IMPACT") || !strings.Contains(stdout, "formula: weightedTotal=") {
		t.Fatalf("human code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
}

func TestRiskRejectsInvalidBoundsAndIdentity(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"risk", "--top", "0"},
		{"risk", "--max-paths", "0"},
		{"risk", "--max-expanded", "0"},
		{"risk", "--identity", "robot:alice"},
	}
	for _, args := range tests {
		code, _, stderr := execute(args...)
		if code != 2 || stderr == "" {
			t.Fatalf("args = %v code = %d stderr = %q", args, code, stderr)
		}
	}
}

func riskCLISnapshot() snapshot.Snapshot {
	roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "token-minter"}
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata:     snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true}},
		Identities:   []snapshot.Identity{{Kind: snapshot.IdentityUser, Name: "alice"}},
		Roles:        []snapshot.Role{{Ref: roleRef, Rules: []snapshot.PolicyRule{{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"admin"}}}}},
		Bindings: []snapshot.Binding{{
			Ref:     snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "token-minter"},
			RoleRef: roleRef, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
		}},
		ServiceAccounts: []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "admin"}}},
	}
}
