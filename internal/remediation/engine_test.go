package remediation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestGenerateRanksMeasuredClusterAdminRemediationDeterministically(t *testing.T) {
	t.Parallel()
	value := clusterAdminSnapshot()
	beforeDigest, err := snapshot.SemanticDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Generate(context.Background(), value, Options{MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(context.Background(), value, Options{MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("remediation result is not byte-stable")
	}
	if first.Summary.Recommended == 0 || len(first.Candidates) == 0 {
		t.Fatalf("summary = %+v, want a recommended candidate", first.Summary)
	}
	best := first.Candidates[0]
	if best.Kind != KindRemoveSubject || best.Disposition != DispositionRecommended {
		t.Fatalf("best candidate = %+v", best)
	}
	if best.Impact.Risk.Cluster.Delta >= 0 || len(best.Impact.RemovedPathIDs) == 0 {
		t.Fatalf("candidate did not measurably reduce risk: %+v", best.Impact)
	}
	if best.ID == "" || best.Ranking.Rank != 1 || !best.Ranking.ParetoOptimal {
		t.Fatalf("unstable or unranked candidate: %+v", best)
	}
	afterDigest, err := snapshot.SemanticDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	if beforeDigest != afterDigest {
		t.Fatal("candidate simulation mutated its input snapshot")
	}
}

func TestRedundantGrantIsEvaluatedButNotRecommended(t *testing.T) {
	t.Parallel()
	value := tokenSnapshot()
	copyBinding := value.Bindings[0]
	copyBinding.Ref.Name = "token-minter-copy"
	value.Bindings = append(value.Bindings, copyBinding)
	result, err := Generate(context.Background(), value, Options{MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000, IncludeDominated: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range result.Candidates {
		if candidate.Kind == KindRemoveSubject && candidate.Disposition == DispositionIneffective {
			found = true
			if candidate.Impact.UnresolvedGrantChanges == 0 || candidate.Benefit.Total != 0 {
				t.Fatalf("redundant candidate impact = %+v", candidate)
			}
		}
	}
	if !found {
		t.Fatalf("candidates = %+v, want ineffective redundant-grant candidate", result.Candidates)
	}
}

func TestHostEscapeProducesMeasuredPSACandidate(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.APIResources = append(value.APIResources, snapshot.APIResource{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true})
	value.Roles = []snapshot.Role{{
		Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "pod-creator"},
		Rules: []snapshot.PolicyRule{{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
	}}
	value.Bindings = []snapshot.Binding{{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "pod-creators"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "pod-creator"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	}}
	value.Assets = []snapshot.Asset{{Ref: snapshot.ObjectRef{Kind: "Node", Name: "worker-1"}, AssetType: "Node"}}
	result, err := Generate(context.Background(), value, Options{MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000, IncludeDominated: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range result.Candidates {
		if candidate.Kind != KindEnforcePSA {
			continue
		}
		found = true
		if candidate.Benefit.BlockedPaths == 0 || candidate.Impact.Risk.Cluster.Delta >= 0 {
			t.Fatalf("PSA candidate was not measured as blocking: %+v", candidate)
		}
	}
	if !found {
		t.Fatal("no PSA candidate generated")
	}
}

func TestGenerateHonorsBoundsAndCancellation(t *testing.T) {
	t.Parallel()
	value := tokenSnapshot()
	result, err := Generate(context.Background(), value, Options{MaxCandidates: 1, MaxPaths: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated || result.Summary.Evaluated != 1 || result.Summary.Generated <= 1 {
		t.Fatalf("bounded result = %+v", result.Summary)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Generate(ctx, value, Options{}); err == nil {
		t.Fatal("Generate() error = nil, want cancellation")
	}
}

func BenchmarkGenerate(b *testing.B) {
	value := tokenSnapshot()
	for b.Loop() {
		if _, err := Generate(context.Background(), value, Options{MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000}); err != nil {
			b.Fatal(err)
		}
	}
}

func baseSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
		},
	}
}

func clusterAdminSnapshot() snapshot.Snapshot {
	value := baseSnapshot()
	value.Roles = []snapshot.Role{{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}, Rules: []snapshot.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}}}}
	value.Bindings = []snapshot.Binding{{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "admins"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	}}
	return value
}

func tokenSnapshot() snapshot.Snapshot {
	value := baseSnapshot()
	value.ServiceAccounts = []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "admin"}}}
	value.Roles = []snapshot.Role{{
		Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "token-minter"},
		Rules: []snapshot.PolicyRule{{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"admin"}}},
	}}
	value.Bindings = []snapshot.Binding{{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "token-minters"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "token-minter"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	}}
	return value
}
