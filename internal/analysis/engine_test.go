package analysis_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestBuiltinRulesHaveStableUniqueMetadata(t *testing.T) {
	t.Parallel()
	rules := analysis.BuiltinRules()
	if len(rules) != 32 {
		t.Fatalf("rules = %d, want 32", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		metadata := rule.Metadata()
		if _, exists := seen[metadata.ID]; exists {
			t.Fatalf("duplicate rule ID %q", metadata.ID)
		}
		seen[metadata.ID] = struct{}{}
		if metadata.RiskScore < 0 || metadata.RiskScore > 100 || metadata.Title == "" || len(metadata.Recommendations) == 0 || len(metadata.References) == 0 {
			t.Fatalf("incomplete metadata for %s: %#v", metadata.ID, metadata)
		}
	}
}

func TestAnalyzeDetectsRBACAndWorkloadFindingsWithEvidence(t *testing.T) {
	t.Parallel()
	result := mustAnalyze(t, dangerousSnapshot())
	wanted := []string{"RBACVIZ-R001", "RBACVIZ-R002", "RBACVIZ-R003", "RBACVIZ-R004", "RBACVIZ-R005", "RBACVIZ-R006", "RBACVIZ-R007", "RBACVIZ-R009", "RBACVIZ-R017", "RBACVIZ-R024", "RBACVIZ-R025", "RBACVIZ-R028", "RBACVIZ-R029", "RBACVIZ-R032"}
	got := make(map[string]bool)
	for _, finding := range result.Findings {
		got[finding.RuleID] = true
		if finding.ID == "" || len(finding.Evidence) == 0 || finding.Confidence == "" || len(finding.Recommendations) == 0 {
			t.Fatalf("finding lacks required evidence contract: %#v", finding)
		}
	}
	for _, ruleID := range wanted {
		if !got[ruleID] {
			t.Errorf("missing finding for %s", ruleID)
		}
	}
	if !result.Complete || result.SchemaVersion != analysis.ResultSchemaVersion || result.RulesetVersion != analysis.RulesetVersion {
		t.Fatalf("unexpected result metadata: %#v", result)
	}
}

func TestRuleCanBeEvaluatedIndependently(t *testing.T) {
	t.Parallel()
	var secretRule analysis.Rule
	for _, rule := range analysis.BuiltinRules() {
		if rule.Metadata().ID == "RBACVIZ-R007" {
			secretRule = rule
		}
	}
	if secretRule == nil {
		t.Fatal("secret rule not found")
	}
	value := baseSnapshot()
	value.Roles = []snapshot.Role{{
		Ref:   snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "Role", Namespace: "prod", Name: "secret-reader"},
		Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}}},
	}}
	value.Bindings = []snapshot.Binding{{
		Ref:      snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "RoleBinding", Namespace: "prod", Name: "secret-reader"},
		RoleRef:  snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "Role", Namespace: "prod", Name: "secret-reader"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	}}
	engine, err := analysis.New(value, secretRule)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rules) != 1 || len(result.Findings) != 1 || result.Findings[0].RuleID != "RBACVIZ-R007" || result.Findings[0].Evidence[0].Grant == nil {
		t.Fatalf("independent rule result = %#v", result)
	}
}

func TestFindingsAreDeterministicAcrossInputOrder(t *testing.T) {
	t.Parallel()
	value := dangerousSnapshot()
	forward := mustAnalyze(t, value)
	slices.Reverse(value.Roles)
	slices.Reverse(value.Bindings)
	slices.Reverse(value.Workloads)
	reverse := mustAnalyze(t, value)
	left, _ := json.Marshal(forward)
	right, _ := json.Marshal(reverse)
	if string(left) != string(right) {
		t.Fatalf("findings changed with input order:\n%s\n%s", left, right)
	}
}

func TestIncompleteCollectionPropagatesWithoutSuppressingFindings(t *testing.T) {
	t.Parallel()
	value := dangerousSnapshot()
	value.Metadata.Complete = false
	value.Warnings = []snapshot.Warning{{Resource: "roles", Code: "Forbidden", Message: "collection denied"}}
	result := mustAnalyze(t, value)
	if result.Complete || len(result.Warnings) == 0 || len(result.Findings) == 0 {
		t.Fatalf("partial result lost warning or findings: %#v", result)
	}
}

func TestAnalyzeHonorsCancellation(t *testing.T) {
	t.Parallel()
	engine, err := analysis.New(dangerousSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Analyze(ctx); err == nil {
		t.Fatal("Analyze() error = nil after cancellation")
	}
}

func FuzzFindingDeterminism(f *testing.F) {
	for _, seed := range []string{"alice", "system:serviceaccount:prod:api", "team@example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 1024 || strings.TrimSpace(name) == "" || strings.ContainsRune(name, '\x00') {
			t.Skip()
		}
		value := dangerousSnapshot()
		value.Bindings[0].Subjects = []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: name}}
		left := mustAnalyze(t, value)
		right := mustAnalyze(t, value)
		leftJSON, _ := json.Marshal(left)
		rightJSON, _ := json.Marshal(right)
		if string(leftJSON) != string(rightJSON) {
			t.Fatal("identical analysis input produced different output")
		}
	})
}

func BenchmarkAnalyze(b *testing.B) {
	engine, err := analysis.New(dangerousSnapshot())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		if _, err := engine.Analyze(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func mustAnalyze(t *testing.T, value snapshot.Snapshot) analysis.Result {
	t.Helper()
	engine, err := analysis.New(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

const rbacGroup = "rbac.authorization.k8s.io"

func baseSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "users", Kind: "User", Namespaced: false},
			{GroupVersion: "rbac.authorization.k8s.io/v1", APIGroup: rbacGroup, Version: "v1", Name: "clusterroles", Kind: "ClusterRole", Namespaced: false},
		},
	}
}

func dangerousSnapshot() snapshot.Snapshot {
	value := baseSnapshot()
	value.Roles = []snapshot.Role{{
		Ref: snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "ClusterRole", Name: "cluster-admin"},
		Rules: []snapshot.PolicyRule{
			{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
			{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}},
			{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}},
			{Verbs: []string{"impersonate"}, APIGroups: []string{""}, Resources: []string{"users"}},
			{Verbs: []string{"bind", "escalate"}, APIGroups: []string{rbacGroup}, Resources: []string{"clusterroles"}},
		},
	}}
	value.Bindings = []snapshot.Binding{
		{
			Ref:      snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "ClusterRoleBinding", Name: "admins"},
			RoleRef:  snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}, {Kind: snapshot.IdentityGroup, Name: "system:masters"}},
		},
		{
			Ref:      snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "RoleBinding", Namespace: "prod", Name: "namespace-admins"},
			RoleRef:  snapshot.ObjectRef{APIGroup: rbacGroup, Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "bob"}},
		},
	}
	value.Workloads = []snapshot.Workload{{
		Ref: snapshot.ObjectRef{Kind: "Pod", Namespace: "prod", Name: "danger"}, HostNetwork: true,
		PrivilegedContainers: []string{"root-shell"}, Volumes: []snapshot.VolumeReference{{Name: "host", Kind: "HostPath", Target: "/"}},
	}}
	return value
}
