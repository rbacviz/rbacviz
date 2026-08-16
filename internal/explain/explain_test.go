package explain

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestBuildExplainsRoleBindingToClusterRoleWithAnalysis(t *testing.T) {
	t.Parallel()
	input := accessSnapshot()
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	identity := permission.Identity{Kind: snapshot.IdentityServiceAccount, Namespace: "prod", Name: "backend"}
	resolver, err := permission.New(canonical)
	if err != nil {
		t.Fatal(err)
	}
	permissions := resolver.Permissions(identity, nil)
	var dangerous permission.Capability
	for _, capability := range permissions.Capabilities {
		if capability.Verb == "delete" && capability.Resource == "secrets" {
			dangerous = capability
			break
		}
	}
	if len(dangerous.Grants) != 1 {
		t.Fatalf("dangerous grants = %d, want 1", len(dangerous.Grants))
	}
	finding := analysis.Finding{
		ID: "finding-delete-secrets", RuleID: "RBACVIZ-TEST", Title: "ServiceAccount can delete Secrets",
		Severity: analysis.SeverityHigh, RiskScore: 80, Confidence: analysis.ConfidenceConfirmed,
		SecurityImpact:     "Deleting Secrets can disrupt workloads and credential delivery.",
		AffectedIdentities: []permission.Identity{identity},
		AffectedObjects:    []snapshot.ObjectRef{dangerous.Grants[0].BindingRef, dangerous.Grants[0].RoleRef},
		Evidence: []analysis.Evidence{
			{Grant: &dangerous.Grants[0]},
			{Permission: &analysis.PermissionEvidence{Verb: dangerous.Verb, APIGroup: dangerous.APIGroup, Resource: dangerous.Resource, Scope: dangerous.Scope, Namespace: dangerous.Namespace}},
		},
		Recommendations: []string{"Remove delete on secrets or bind the ServiceAccount to a narrower Role."},
	}
	graph, err := graphmodel.Build(canonical)
	if err != nil {
		t.Fatal(err)
	}
	findings := analysis.Result{SchemaVersion: analysis.ResultSchemaVersion, Complete: true, Findings: []analysis.Finding{finding}}
	risks := risk.Result{SchemaVersion: risk.ResultSchemaVersion, Complete: true}
	first, err := Build(context.Background(), canonical, graph.Nodes(), findings, attackpath.Result{}, risks)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), canonical, graph.Nodes(), findings, attackpath.Result{}, risks)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("access explanations are not deterministic")
	}

	values := first.Lookup(canonical.ServiceAccounts[0].ID)
	if len(values) != 1 {
		t.Fatalf("ServiceAccount explanations = %d, want 1", len(values))
	}
	value := values[0]
	if value.Binding.Kind != "RoleBinding" || value.Role.Kind != "ClusterRole" || value.Analysis.Status != StatusObservation || value.Analysis.Priority != PriorityP2 {
		t.Fatalf("unexpected explanation: %+v", value)
	}
	if len(value.Workloads) != 1 || value.Workloads[0].Kind != "Deployment" {
		t.Fatalf("workloads = %+v, want backend Deployment", value.Workloads)
	}
	if len(value.FindingIDs) != 1 || value.FindingIDs[0] != finding.ID {
		t.Fatalf("finding IDs = %+v", value.FindingIDs)
	}
	tree := RenderTree(value)
	for _, wanted := range []string{"Deployment prod/backend", "ServiceAccount prod/backend", "RoleBinding prod/backend-rb", "ClusterRole developer", "effective scope: namespace prod", "delete secrets [HIGH · CONFIRMED]"} {
		if !strings.Contains(tree, wanted) {
			t.Fatalf("access tree lacks %q:\n%s", wanted, tree)
		}
	}
	if strings.Contains(tree, "delete/get secrets") || strings.Contains(tree, "get secrets [HIGH") {
		t.Fatalf("security classification leaked to a benign verb:\n%s", tree)
	}
	analysisText := RenderAnalysis(value)
	for _, wanted := range []string{"Priority: P2", "Status: OBSERVATION", "Root cause:", "kubectl auth can-i delete secrets"} {
		if !strings.Contains(analysisText, wanted) {
			t.Fatalf("analysis lacks %q:\n%s", wanted, analysisText)
		}
	}
}

func TestCapabilityLookupKeepsIndependentGrantChains(t *testing.T) {
	t.Parallel()
	input := accessSnapshot()
	input.Bindings = append(input.Bindings, snapshot.Binding{
		Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "backend-rb-secondary"},
		RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "developer"},
		Subjects: []snapshot.Subject{{Kind: snapshot.IdentityServiceAccount, Namespace: "prod", Name: "backend"}},
	})
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := graphmodel.Build(canonical)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Build(context.Background(), canonical, graph.Nodes(), analysis.Result{Complete: true}, attackpath.Result{}, risk.Result{Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	capabilityID := ""
	for _, node := range graph.Nodes() {
		if node.Type == graphmodel.NodeCapability && node.Capability != nil && node.Capability.Verb == "delete" && node.Capability.Resource == "secrets" {
			capabilityID = node.ID
			break
		}
	}
	if capabilityID == "" {
		t.Fatal("delete secrets capability node was not found")
	}
	values := result.Lookup(capabilityID)
	if len(values) != 2 {
		t.Fatalf("capability explanations = %d, want 2 independent binding chains", len(values))
	}
	if values[0].Binding.Name == values[1].Binding.Name {
		t.Fatalf("bindings were collapsed: %+v", values)
	}
}

func TestBuildHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Build(ctx, accessSnapshot(), nil, analysis.Result{}, attackpath.Result{}, risk.Result{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func accessSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "configmaps", Kind: "ConfigMap", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
		},
		Roles: []snapshot.Role{{
			Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "developer"},
			Rules: []snapshot.PolicyRule{
				{Verbs: []string{"get", "list", "watch"}, APIGroups: []string{""}, Resources: []string{"pods"}},
				{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"configmaps"}},
				{Verbs: []string{"delete", "get"}, APIGroups: []string{""}, Resources: []string{"secrets"}},
			},
		}},
		Bindings: []snapshot.Binding{{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "backend-rb"},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "developer"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityServiceAccount, Namespace: "prod", Name: "backend"}},
		}},
		ServiceAccounts: []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "backend"}}},
		Workloads:       []snapshot.Workload{{Ref: snapshot.ObjectRef{APIGroup: "apps", Kind: "Deployment", Namespace: "prod", Name: "backend"}, ServiceAccountName: "backend"}},
	}
}
