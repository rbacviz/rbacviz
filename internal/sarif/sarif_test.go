package sarif_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/sarif"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestWriteProducesSARIF21WithStableFingerprintAndEvidence(t *testing.T) {
	t.Parallel()
	ref := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "admins"}
	input := analysis.Result{
		SchemaVersion: analysis.ResultSchemaVersion, RulesetVersion: analysis.RulesetVersion, Complete: true,
		Rules:    []analysis.RuleMetadata{{ID: "RBACVIZ-R001", Title: "Cluster admin", Severity: analysis.SeverityCritical, RiskScore: 98, Description: "admin grant", SecurityImpact: "cluster compromise", References: []string{"https://example.invalid/rule"}}},
		Findings: []analysis.Finding{{ID: "RBACVIZ-ABC", RuleID: "RBACVIZ-R001", Title: "Cluster admin", Severity: analysis.SeverityCritical, RiskScore: 98, Confidence: analysis.ConfidenceConfirmed, Description: "admin binding", AffectedObjects: []snapshot.ObjectRef{ref}, Evidence: []analysis.Evidence{{Kind: "ObjectField", Ref: &ref, Field: "roleRef"}}}},
		Warnings: []analysis.Warning{},
	}
	var output bytes.Buffer
	if err := sarif.Write(&output, input); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, output.String())
	}
	for _, required := range []string{`"version": "2.1.0"`, `"ruleId": "RBACVIZ-R001"`, `"rbacvizFindingId/v1": "RBACVIZ-ABC"`, `"finding":`, `kubernetes:///rbac.authorization.k8s.io/ClusterRoleBinding/admins`} {
		if !strings.Contains(output.String(), required) {
			t.Errorf("SARIF lacks %q:\n%s", required, output.String())
		}
	}
}
