package report

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestBuildAcceptedExceptionPreservesEvidenceAndAdjustsActiveRisk(t *testing.T) {
	t.Parallel()
	policy := baseline.Document{SchemaVersion: baseline.SchemaVersion, Profile: baseline.ProfileDevelopment, Suppressions: []baseline.Suppression{{
		ID: "cluster-admin-reviewed", RootCauseKey: "grant|rbac.authorization.k8s.io|ClusterRoleBinding||admins|user:alice", Subject: "user:alice",
		Reason: "Required by the synthetic administrative workflow", Owner: "platform-security",
		Ticket: "SEC-42", Expires: "2026-10-01",
	}}}
	result, err := Build(context.Background(), reportClusterAdminSnapshot(), Options{MaxIssues: 50, MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000, Baseline: &policy, EvaluatedAt: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Baseline == nil || len(result.AcceptedExceptions) != 1 || result.Summary.AcceptedExceptions != 1 {
		t.Fatalf("accepted baseline entry missing: %+v", result)
	}
	accepted := result.AcceptedExceptions[0]
	if len(accepted.FindingIDs) == 0 || len(accepted.RiskFamilyIDs) == 0 || len(accepted.Issues) == 0 || len(accepted.Issues[0].Evidence) == 0 {
		t.Fatalf("accepted exception lost correlated evidence: %+v", accepted)
	}
	if result.Summary.RiskIndex >= accepted.Issues[0].MaxPathRisk {
		t.Fatalf("active risk was not adjusted: summary=%+v accepted=%+v", result.Summary, accepted.Issues[0])
	}
	var output strings.Builder
	if err := WriteMarkdown(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"## Accepted exceptions", "cluster-admin-reviewed", "platform-security", "SEC-42", "excluded from the active Risk Index", "Evidence:"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("Markdown lacks %q:\n%s", wanted, output.String())
		}
	}
}

func TestBuildGroupsCorrelatedSignalsAndAttachesMeasuredFix(t *testing.T) {
	t.Parallel()
	value := reportClusterAdminSnapshot()
	first, err := Build(context.Background(), value, Options{MaxIssues: 50, MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), value, Options{MaxIssues: 50, MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("report is not deterministic")
	}
	if first.Summary.RawFindings <= first.Summary.RootCauses {
		t.Fatalf("raw findings = %d root causes = %d, want correlated findings to be grouped", first.Summary.RawFindings, first.Summary.RootCauses)
	}
	if first.Summary.RiskModelVersion == "" || first.Summary.RiskFamilies == 0 || first.Summary.ContributingRiskFamilies == 0 {
		t.Fatalf("risk family summary is incomplete: %+v", first.Summary)
	}
	if len(first.Issues) == 0 || first.Issues[0].Priority != PriorityP0 {
		t.Fatalf("issues = %+v, want a P0 issue", first.Issues)
	}
	if len(first.Issues[0].Fixes) == 0 || first.Issues[0].Fixes[0].RiskDelta >= 0 {
		t.Fatalf("fixes = %+v, want a measured risk reduction", first.Issues[0].Fixes)
	}
	if first.Issues[0].RootCauseKey == "" || len(first.Issues[0].FindingIDs) < 2 {
		t.Fatalf("root cause was not correlated: %+v", first.Issues[0])
	}
	if len(first.Issues[0].AccessExplanations) == 0 || len(first.Issues[0].AccessExplanations[0].Capabilities) == 0 {
		t.Fatalf("access chain was not attached: %+v", first.Issues[0])
	}
}

func TestWriteMarkdownContainsDecisionReadySections(t *testing.T) {
	t.Parallel()
	result, err := Build(context.Background(), reportClusterAdminSnapshot(), Options{MaxIssues: 50, MaxCandidates: 20, MaxPaths: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteMarkdown(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"Risk Index is a posture indicator", "Risk model", "Risk families", "Unique root causes", "Priority remediation plan", "Access chain", "ClusterRole cluster-admin", "Virtually evaluated fixes", "kubectl auth can-i", "RBACVIZ did not apply any change"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("Markdown report lacks %q:\n%s", wanted, output.String())
		}
	}
}

func reportClusterAdminSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", Context: "kind-devsecops-lab", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
			{GroupVersion: "rbac.authorization.k8s.io/v1", APIGroup: "rbac.authorization.k8s.io", Version: "v1", Name: "clusterroles", Kind: "ClusterRole"},
		},
		Roles: []snapshot.Role{{
			Ref:   snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
			Rules: []snapshot.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		}},
		Bindings: []snapshot.Binding{{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "admins"},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
		}},
	}
}
