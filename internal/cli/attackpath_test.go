package cli_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestAttackPathOfflineHumanAndJSONContracts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "attack-path.json")
	roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "token-minter"}
	value := snapshot.Snapshot{
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
	if err := snapshot.Save(path, value); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := execute("attack-path", "--from", "user:alice", "--to", "service-account-takeover", "--namespace", "prod", "--top", "3", "--snapshot", path, "--output", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("code = %d stderr = %q", code, stderr)
	}
	var result attackpath.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(result.Paths) != 1 || result.Paths[0].TemplateID != "RBACVIZ-AP003" || result.Paths[0].Steps[0].Evidence[1].Grant == nil {
		t.Fatalf("unexpected machine contract: %#v", result)
	}

	code, stdout, stderr = execute("attack-path", "--from", "user:alice", "--to", "service-account-takeover", "--snapshot", path)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "grant:") || !strings.Contains(stdout, "prerequisite:") || !strings.Contains(stdout, "remediation candidate:") {
		t.Fatalf("human code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
}

func TestAttackPathRejectsInvalidTargetAndBounds(t *testing.T) {
	t.Parallel()
	code, _, stderr := execute("attack-path", "--to", "root-everywhere")
	if code != 2 || !strings.Contains(stderr, "unknown privilege target") {
		t.Fatalf("target code = %d stderr = %q", code, stderr)
	}
	code, _, stderr = execute("attack-path", "--top", "0")
	if code != 2 || !strings.Contains(stderr, "--top must be between") {
		t.Fatalf("top code = %d stderr = %q", code, stderr)
	}
}
