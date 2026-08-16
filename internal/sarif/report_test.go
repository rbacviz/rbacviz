package sarif_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/report"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/sarif"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestWriteReportProducesDeterministicRootCauseSARIF(t *testing.T) {
	t.Parallel()
	active := report.Issue{
		ID: "issue-active", RootCauseKey: "grant|active", RootCause: "RoleBinding prod/backend-rb grants ClusterRole developer",
		Title: "Backend can delete secrets", Priority: report.PriorityP1, Severity: analysis.SeverityHigh,
		Actionability: report.ActionabilityActionable, MaxPathRisk: 82, SecurityImpact: "Credentials can be disrupted",
		RuleIDs: []string{"RBACVIZ-R004"}, FindingIDs: []string{"finding-active"},
		AffectedObjects: []snapshot.ObjectRef{{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "backend-rb"}},
	}
	accepted := report.Issue{
		ID: "issue-accepted", RootCauseKey: "grant|accepted", RootCause: "ClusterRoleBinding grants cluster-admin",
		Title: "Reviewed administrative binding", Priority: report.PriorityP3, Severity: analysis.SeverityCritical,
		Actionability: report.ActionabilityAccepted, MaxPathRisk: 100, RuleIDs: []string{"RBACVIZ-R001"},
		AffectedObjects: []snapshot.ObjectRef{{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "admins"}},
	}
	value := report.Result{
		SchemaVersion: report.ResultSchemaVersion, ModelVersion: report.ModelVersion, ToolVersion: "v0.2.0",
		Complete: false, Summary: report.Summary{RiskIndex: 82, RiskSeverity: risk.SeverityHigh, RootCauses: 1},
		Issues: []report.Issue{active},
		AcceptedExceptions: []report.Exception{{
			Suppression: baseline.Suppression{ID: "admin-reviewed", Reason: "Break-glass access", Owner: "platform-security", Expires: "2099-01-01", Ticket: "SEC-42"},
			State:       baseline.StateAccepted, Issues: []report.Issue{accepted},
		}},
		Warnings: []report.Warning{{Source: "collector", Code: "PARTIAL_COLLECTION", Message: "secrets were inaccessible"}},
	}
	var first, second bytes.Buffer
	if err := sarif.WriteReport(&first, value); err != nil {
		t.Fatal(err)
	}
	if err := sarif.WriteReport(&second, value); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("report SARIF is not deterministic")
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, first.String())
	}
	for _, required := range []string{
		`"version": "2.1.0"`, `"reportModelVersion": "1.2.0"`,
		`"sarifMappingVersion": "1.0.0"`,
		`"rbacvizIssueId/v1": "issue-active"`, `"rbacvizRootCause/v1":`,
		`kubernetes:///rbac.authorization.k8s.io/RoleBinding/prod/backend-rb`,
		`"kind": "external"`, `"status": "accepted"`, `"fullyAccepted": true`,
		`"id": "PARTIAL_COLLECTION"`, `"complete": false`,
	} {
		if !strings.Contains(first.String(), required) {
			t.Errorf("report SARIF lacks %q:\n%s", required, first.String())
		}
	}
}

func TestWriteReportDoesNotSuppressPartiallyAcceptedRootCause(t *testing.T) {
	t.Parallel()
	issue := report.Issue{
		ID: "issue-shared", RootCauseKey: "grant|shared", Title: "Shared broad grant",
		Priority: report.PriorityP1, Severity: analysis.SeverityHigh,
		Actionability: report.ActionabilityActionable, RuleIDs: []string{"RBACVIZ-R004", "RBACVIZ-R009"},
	}
	value := report.Result{
		SchemaVersion: report.ResultSchemaVersion, ModelVersion: report.ModelVersion,
		Complete: true, Issues: []report.Issue{issue},
		AcceptedExceptions: []report.Exception{{
			Suppression: baseline.Suppression{ID: "one-rule-only", Reason: "Reviewed one signal", Owner: "security", Expires: "2099-01-01"},
			State:       baseline.StateAccepted, Issues: []report.Issue{issue},
		}},
	}
	var output bytes.Buffer
	if err := sarif.WriteReport(&output, value); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				Suppressions []any `json:"suppressions"`
				Properties   struct {
					PartiallyAccepted bool `json:"partiallyAccepted"`
					FullyAccepted     bool `json:"fullyAccepted"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF shape: %+v", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if len(result.Suppressions) != 0 || !result.Properties.PartiallyAccepted || result.Properties.FullyAccepted {
		t.Fatalf("partial exception suppressed the complete root cause: %+v", result)
	}
}
