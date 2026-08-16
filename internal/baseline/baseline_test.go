package baseline_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestLoadRejectsWildcardsUnknownFieldsAndMissingReviewMetadata(t *testing.T) {
	t.Parallel()
	for _, payload := range []string{
		"schemaVersion: '1.0'\nprofile: development\nunknown: true\nsuppressions: []\n",
		"schemaVersion: '1.0'\nprofile: development\nsuppressions:\n- id: broad\n  rule: 'RBAC-*'\n  subject: user:alice\n  reason: required\n  owner: platform\n  expires: '2026-10-01'\n",
		"schemaVersion: '1.0'\nprofile: development\nsuppressions:\n- id: unreviewed\n  rule: RBACVIZ-R001\n  expires: '2026-10-01'\n",
	} {
		path := filepath.Join(t.TempDir(), "baseline.yaml")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := baseline.Load(path); err == nil {
			t.Fatalf("Load accepted invalid baseline:\n%s", payload)
		}
	}
}

func TestEvaluateKeepsAcceptedExpiredAndUnmatchedSeparate(t *testing.T) {
	t.Parallel()
	binding := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "reader"}
	identity := permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}
	grant := permission.GrantEvidence{ID: "grant-1", BindingRef: binding, Subject: snapshot.Subject{Kind: snapshot.IdentityUser, Name: "alice"}}
	findings := analysis.Result{Findings: []analysis.Finding{{ID: "finding-1", RuleID: "RBACVIZ-R001", AffectedIdentities: []permission.Identity{identity}, Evidence: []analysis.Evidence{{Grant: &grant}}}}}
	risks := risk.Result{RiskFamilies: []risk.Family{{ID: "family-1", RootCauseKey: "grant|rbac.authorization.k8s.io|RoleBinding|prod|reader|user:alice", Source: identity, BindingRef: &binding}}}
	document := baseline.Document{SchemaVersion: baseline.SchemaVersion, Profile: baseline.ProfileDevelopment, Suppressions: []baseline.Suppression{
		{ID: "accepted", Rule: "RBACVIZ-R001", Subject: "user:alice", Reason: "reviewed requirement", Owner: "platform", Expires: "2026-10-01"},
		{ID: "expired", Rule: "RBACVIZ-R001", Subject: "user:alice", Reason: "old review", Owner: "platform", Expires: "2026-07-01"},
		{ID: "stale", Rule: "RBACVIZ-R999", Subject: "user:alice", Reason: "no longer present", Owner: "platform", Expires: "2026-10-01"},
	}}
	result := baseline.Evaluate(document, findings, risks, time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC))
	if len(result.Accepted) != 1 || len(result.Expired) != 1 || len(result.Unmatched) != 1 {
		t.Fatalf("unexpected evaluation: %+v", result)
	}
	if len(result.Accepted[0].RiskFamilyIDs) != 0 {
		t.Fatalf("a rule-only exception broadened into a risk-family exception: %+v", result.Accepted[0])
	}
}
