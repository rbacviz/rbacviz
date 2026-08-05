package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestCompareReportsSecuritySemanticDeltaDeterministically(t *testing.T) {
	t.Parallel()
	before := testSnapshot()
	after := testSnapshot()
	after.Metadata.CollectedAt = "2026-08-05T13:00:00Z"
	after.Roles = append(after.Roles, snapshot.Role{
		Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "danger"},
		Rules: []snapshot.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
	})
	after.Bindings = append(after.Bindings, snapshot.Binding{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "danger"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "danger"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	})

	first, err := Compare(context.Background(), before, after, Options{MaxPaths: 1000, MaxExpanded: 10000})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compare(context.Background(), before, after, Options{MaxPaths: 1000, MaxExpanded: 10000})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("identical semantic comparison was not byte-stable")
	}
	if first.Summary.PermissionsAdded == 0 || first.Summary.DangerousCapabilitiesNew == 0 {
		t.Fatalf("permission summary = %+v, want added dangerous access", first.Summary)
	}
	if first.Summary.FindingsAdded == 0 || first.Summary.AttackPathsAdded == 0 {
		t.Fatalf("analysis summary = %+v, want finding and path additions", first.Summary)
	}
	if first.Risk.Cluster.Delta <= 0 {
		t.Fatalf("cluster risk delta = %d, want positive", first.Risk.Cluster.Delta)
	}
	if first.BeforeSemanticDigest == first.AfterSemanticDigest {
		t.Fatal("semantic digests unexpectedly match")
	}
}

func TestCompareSeparatesGrantChurnFromPermissionChange(t *testing.T) {
	t.Parallel()
	before := testSnapshot()
	after := testSnapshot()
	after.Bindings = append(after.Bindings, snapshot.Binding{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "readers-copy"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	})

	result, err := Compare(context.Background(), before, after, Options{MaxPaths: 1000, MaxExpanded: 10000})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.PermissionsAdded != 0 || result.Summary.PermissionsRemoved != 0 {
		t.Fatalf("permissions changed for duplicate grant: %+v", result.Summary)
	}
	if result.Summary.PermissionGrantsChanged == 0 {
		t.Fatal("duplicate binding provenance change was not reported")
	}
	if result.Summary.AttackPathsAdded != 0 || result.Summary.AttackPathsRemoved != 0 {
		t.Fatalf("parallel grant inflated semantic paths: %+v", result.Summary)
	}
}

func TestCompareReportsControlModification(t *testing.T) {
	t.Parallel()
	before := testSnapshot()
	after := testSnapshot()
	before.SecurityControls = []snapshot.SecurityControl{{
		Ref: snapshot.ObjectRef{Kind: "Namespace", Name: "prod"}, ControlType: "PodSecurityAdmission", Mode: "baseline",
		Details: []snapshot.KeyValue{{Key: "pod-security.kubernetes.io/enforce", Value: "baseline"}},
	}}
	after.SecurityControls = []snapshot.SecurityControl{{
		Ref: snapshot.ObjectRef{Kind: "Namespace", Name: "prod"}, ControlType: "PodSecurityAdmission", Mode: "restricted",
		Details: []snapshot.KeyValue{{Key: "pod-security.kubernetes.io/enforce", Value: "restricted"}},
	}}
	result, err := Compare(context.Background(), before, after, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Controls.Modified) != 1 || result.Summary.ControlsChanged != 1 {
		t.Fatalf("controls = %+v", result.Controls)
	}
}

func TestCompareHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Compare(ctx, testSnapshot(), testSnapshot(), Options{})
	if err == nil {
		t.Fatal("Compare() error = nil, want cancellation")
	}
}

func BenchmarkCompare(b *testing.B) {
	before := testSnapshot()
	after := testSnapshot()
	after.Roles[0].Rules[0].Verbs = []string{"get", "list"}
	for b.Loop() {
		if _, err := Compare(context.Background(), before, after, Options{MaxPaths: 100, MaxExpanded: 1000}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompare100Identities(b *testing.B) {
	before := testSnapshot()
	before.Roles = nil
	before.Bindings = nil
	for index := 0; index < 100; index++ {
		name := fmt.Sprintf("reader-%03d", index)
		before.Roles = append(before.Roles, snapshot.Role{
			Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: name},
			Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		})
		before.Bindings = append(before.Bindings, snapshot.Binding{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: name},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: name},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: fmt.Sprintf("user-%03d", index)}},
		})
	}
	after := before
	after.Roles = append([]snapshot.Role(nil), before.Roles...)
	after.Roles[99].Rules = []snapshot.PolicyRule{{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}}}
	for b.Loop() {
		if _, err := Compare(context.Background(), before, after, Options{MaxPaths: 1000, MaxExpanded: 10000}); err != nil {
			b.Fatal(err)
		}
	}
}

func testSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
			{GroupVersion: "apps/v1", APIGroup: "apps", Version: "v1", Name: "deployments", Kind: "Deployment", Namespaced: true},
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
