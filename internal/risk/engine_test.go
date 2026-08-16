package risk

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestCalibratedPathScoresAndFormula(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      snapshot.Snapshot
		templateID string
		wantScore  int
		severity   Severity
	}{
		{name: "confirmed cluster admin", input: clusterAdminSnapshot(), templateID: "RBACVIZ-AP001", wantScore: 100, severity: SeverityCritical},
		{name: "likely token minting", input: tokenSnapshot("prod", "alice"), templateID: "RBACVIZ-AP003", wantScore: 77, severity: SeverityHigh},
		{name: "conditional secret inference", input: secretSnapshot(), templateID: "RBACVIZ-AP005", wantScore: 60, severity: SeverityMedium},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := analyzeRisk(t, test.input, Query{MaxPaths: 100, MaxExpanded: 1000})
			value := riskByTemplate(t, result.PathScores, test.templateID)
			if value.Score != test.wantScore || value.Severity != test.severity {
				t.Fatalf("score = %d %s, want %d %s: %#v", value.Score, value.Severity, test.wantScore, test.severity, value)
			}
			if len(value.Factors) != 6 || value.Formula.Numerator <= 0 || value.Formula.Denominator <= 0 {
				t.Fatalf("score explanation is incomplete: %#v", value)
			}
			recomputed := clamp(roundDivide(value.Formula.Numerator, value.Formula.Denominator))
			if recomputed != value.Score {
				t.Fatalf("formula recomputed %d, score is %d", recomputed, value.Score)
			}
		})
	}
}

func TestBlockingControlRetainsImpactAndStronglyReducesRisk(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("prod", "alice", snapshot.PolicyRule{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"pods"}})
	value.Assets = []snapshot.Asset{{Ref: snapshot.ObjectRef{Kind: "Node", Name: "worker"}, AssetType: "Node"}}
	value.SecurityControls = []snapshot.SecurityControl{{Ref: snapshot.ObjectRef{Kind: "Namespace", Name: "prod"}, ControlType: "PodSecurityAdmission", Mode: "restricted"}}
	path := riskByTemplate(t, analyzeRisk(t, value, Query{}).PathScores, "RBACVIZ-AP012")
	if !path.Blocked || path.Mitigation.EffectBasisPts != blockingMitigationBPS || path.Score >= 20 {
		t.Fatalf("blocking mitigation was not applied transparently: %#v", path)
	}
	if factorValue(path.Factors, FactorImpact) != 98 {
		t.Fatalf("underlying impact was hidden: %#v", path.Factors)
	}
}

func TestDuplicateGrantPathsDoNotInflateAggregateRiskUnits(t *testing.T) {
	t.Parallel()
	value := tokenSnapshot("prod", "alice")
	second := value.Bindings[0]
	second.Ref.Name = "token-minter-copy"
	second.ID = ""
	value.Bindings = append(value.Bindings, second)
	result := analyzeRisk(t, value, Query{})
	if result.Cluster.PathCount != 2 || result.Cluster.DistinctRiskUnits != 1 || result.Cluster.AdditionalContribution != 0 {
		t.Fatalf("duplicate grants inflated aggregate: %#v", result.Cluster)
	}
	if result.Cluster.RiskFamilyCount != 2 || result.Cluster.ContributingFamilies != 1 || len(result.RiskFamilies) != 2 {
		t.Fatalf("root causes or semantic deduplication were hidden: %#v %#v", result.Cluster, result.RiskFamilies)
	}
	if len(result.Identities) != 1 || result.Identities[0].DistinctRiskUnits != 1 {
		t.Fatalf("identity aggregate is wrong: %#v", result.Identities)
	}
}

func TestBroadRootCauseCountsOnceAndIndependentFamiliesHaveBoundedWeight(t *testing.T) {
	t.Parallel()
	paths := []PathScore{
		aggregateFixture("family-a", "unit-a", "path-a", 80),
		aggregateFixture("family-a", "unit-b", "path-b", 75),
	}
	one := aggregate(AggregateCluster, "cluster", nil, "", paths)
	if one.Score != 80 || one.RiskFamilyCount != 1 || one.DistinctRiskUnits != 2 || one.AdditionalContribution != 0 {
		t.Fatalf("one broad root cause inflated the index: %#v", one)
	}

	// A redundant binding with the same complete outcome set remains a visible
	// root cause, but does not add posture risk a second time.
	paths = append(paths,
		aggregateFixture("family-b", "unit-a", "path-c", 80),
		aggregateFixture("family-b", "unit-b", "path-d", 75),
	)
	redundant := aggregate(AggregateCluster, "cluster", nil, "", paths)
	if redundant.Score != 80 || redundant.RiskFamilyCount != 2 || redundant.ContributingFamilies != 1 {
		t.Fatalf("semantically duplicate family inflated the index: %#v", redundant)
	}

	paths = append(paths, aggregateFixture("family-c", "unit-c", "path-e", 70))
	independent := aggregate(AggregateCluster, "cluster", nil, "", paths)
	if independent.Score != 84 || independent.AdditionalContribution != 4 || independent.ContributingFamilies != 2 {
		t.Fatalf("independent family contribution is not calibrated: %#v", independent)
	}
	if len(independent.Contributions) != 2 || independent.Contributions[1].Weight != 5 || independent.Contributions[1].Contribution != 4 {
		t.Fatalf("aggregate arithmetic is not explainable: %#v", independent.Contributions)
	}
}

func TestFamilyDiversityContributionIsCapped(t *testing.T) {
	t.Parallel()
	paths := make([]PathScore, 0, 10)
	for index := 0; index < 10; index++ {
		paths = append(paths, aggregateFixture(
			fmt.Sprintf("family-%02d", index), fmt.Sprintf("unit-%02d", index), fmt.Sprintf("path-%02d", index), 80,
		))
	}
	value := aggregate(AggregateCluster, "cluster", nil, "", paths)
	if value.Score != 90 || value.AdditionalContribution != 10 || len(value.Contributions) != 6 {
		t.Fatalf("unexpected ranked-family calibration: %#v", value)
	}
	if value.AdditionalContribution > maxFamilyDiversityContribution {
		t.Fatalf("family diversity exceeded cap: %#v", value)
	}
}

func TestNamespaceAndIdentityScopesAreExact(t *testing.T) {
	t.Parallel()
	prod := tokenSnapshot("prod", "alice")
	dev := tokenSnapshot("dev", "bob")
	prod.Identities = append(prod.Identities, dev.Identities...)
	prod.Roles = append(prod.Roles, dev.Roles...)
	prod.Bindings = append(prod.Bindings, dev.Bindings...)
	prod.ServiceAccounts = append(prod.ServiceAccounts, dev.ServiceAccounts...)

	result := analyzeRisk(t, prod, Query{Namespace: "prod"})
	if len(result.Namespaces) != 1 || result.Namespaces[0].Namespace != "prod" || len(result.Identities) != 1 || result.Identities[0].Key != "user:alice" {
		t.Fatalf("namespace scope leaked: %#v", result)
	}
	bob := permission.Identity{Kind: snapshot.IdentityUser, Name: "bob"}
	result = analyzeRisk(t, prod, Query{From: &bob})
	if len(result.Identities) != 1 || result.Identities[0].Key != "user:bob" || result.Namespaces[0].Namespace != "dev" {
		t.Fatalf("identity scope leaked: %#v", result)
	}
}

func TestClusterImpactPropagatesToObservedNamespaces(t *testing.T) {
	t.Parallel()
	value := clusterAdminSnapshot()
	value.ServiceAccounts = []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "default"}}}
	result := analyzeRisk(t, value, Query{Namespace: "prod"})
	if len(result.PathScores) == 0 || len(result.Namespaces) != 1 || result.Namespaces[0].Namespace != "prod" {
		t.Fatalf("cluster impact was omitted from observed namespace: %#v", result)
	}
}

func TestRiskResultIsStableAcrossInputOrderAndTimestamp(t *testing.T) {
	t.Parallel()
	value := tokenSnapshot("prod", "alice")
	first := analyzeRisk(t, value, Query{})
	value.Metadata.CollectedAt = "2035-01-01T00:00:00Z"
	for left, right := 0, len(value.APIResources)-1; left < right; left, right = left+1, right-1 {
		value.APIResources[left], value.APIResources[right] = value.APIResources[right], value.APIResources[left]
	}
	second := analyzeRisk(t, value, Query{})
	if !reflect.DeepEqual(first.PathScores, second.PathScores) || !reflect.DeepEqual(first.Cluster, second.Cluster) {
		t.Fatalf("risk output changed with non-semantic input: %#v != %#v", first, second)
	}
}

func TestIncompleteAndTruncatedAnalysisRemainVisible(t *testing.T) {
	t.Parallel()
	value := tokenSnapshot("prod", "alice")
	value.Metadata.Complete = false
	value.Warnings = []snapshot.Warning{{Resource: "roles", Code: "Forbidden", Message: "collection failed"}}
	result := analyzeRisk(t, value, Query{MaxPaths: 1, MaxExpanded: 1})
	if result.Complete || len(result.Warnings) == 0 {
		t.Fatalf("collection gap was hidden: %#v", result)
	}
}

func TestAnalyzeHonorsCancellation(t *testing.T) {
	t.Parallel()
	engine, err := New(tokenSnapshot("prod", "alice"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Analyze(ctx, Query{}); err == nil {
		t.Fatal("Analyze accepted a canceled context")
	}
}

func FuzzPathScoringIsBoundedAndReproducible(f *testing.F) {
	f.Add(85, 60, 3, byte(1), byte(0))
	f.Fuzz(func(t *testing.T, gain, blast, cost int, confidenceByte, mitigationByte byte) {
		confidences := []attackpath.Confidence{attackpath.ConfidenceConfirmed, attackpath.ConfidenceLikely, attackpath.ConfidenceConditional, attackpath.ConfidenceUnknown, attackpath.ConfidenceBlocked}
		states := []attackpath.MitigationState{attackpath.MitigationObserved, attackpath.MitigationPotential, attackpath.MitigationBlocking}
		confidence := confidences[int(confidenceByte)%len(confidences)]
		control := attackpath.MitigationObservation{ID: "control", State: states[int(mitigationByte)%len(states)], Reason: "fixture"}
		path := attackpath.Path{
			ID: "path", TemplateID: "template", Source: permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"},
			Target:     attackpath.PrivilegeTarget{Type: attackpath.TargetRBACControl, Key: "target", PrivilegeGain: gain, BlastRadius: blast},
			Confidence: confidence, Blocked: confidence == attackpath.ConfidenceBlocked,
			Steps: []attackpath.AttackStep{{Cost: attackpath.CostBreakdown{BaseTechnique: cost}, MitigatingControls: []attackpath.MitigationObservation{control}}},
		}
		first := scorePath(path, baseSnapshot(), false)
		second := scorePath(path, baseSnapshot(), false)
		if first.Score < 0 || first.Score > 100 || !reflect.DeepEqual(first, second) {
			t.Fatalf("invalid score: %#v %#v", first, second)
		}
		weight := 0
		for _, factor := range first.Factors {
			weight += factor.Weight
		}
		if weight != 100 {
			t.Fatalf("weights sum to %d", weight)
		}
	})
}

func BenchmarkRiskAnalysis100Identities(b *testing.B) {
	value := baseSnapshot()
	for index := 0; index < 100; index++ {
		name := fmt.Sprintf("user-%03d", index)
		fixture := tokenSnapshot("prod", name)
		value.Identities = append(value.Identities, fixture.Identities...)
		fixture.Roles[0].Ref.Name = name
		fixture.Bindings[0].Ref.Name = name
		fixture.Bindings[0].RoleRef.Name = name
		value.Roles = append(value.Roles, fixture.Roles...)
		value.Bindings = append(value.Bindings, fixture.Bindings...)
	}
	value.ServiceAccounts = tokenSnapshot("prod", "seed").ServiceAccounts
	engine, err := New(value)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := engine.Analyze(context.Background(), Query{}); err != nil {
			b.Fatal(err)
		}
	}
}

func analyzeRisk(t *testing.T, value snapshot.Snapshot, query Query) Result {
	t.Helper()
	engine, err := New(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Analyze(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func riskByTemplate(t *testing.T, values []PathScore, templateID string) PathScore {
	t.Helper()
	for _, value := range values {
		if value.TemplateID == templateID {
			return value
		}
	}
	t.Fatalf("template %s not found: %#v", templateID, values)
	return PathScore{}
}

func factorValue(values []Factor, name FactorName) int {
	for _, value := range values {
		if value.Name == name {
			return value.Value
		}
	}
	return -1
}

func aggregateFixture(family, unit, pathID string, score int) PathScore {
	source := permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}
	key := "grant|" + family + "|" + source.String()
	return PathScore{
		PathID: pathID, TemplateID: "template-" + unit, Source: source,
		Target:     attackpath.PrivilegeTarget{Type: attackpath.TargetRBACControl, Key: unit},
		Confidence: attackpath.ConfidenceLikely, Score: score, Severity: severity(score),
		RiskUnit: source.String() + "\x00" + unit, RootCauseKey: key,
		RootCause: "fixture " + family, RiskFamilyID: stableID("family", key),
	}
}

func baseSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true},
		},
	}
}

func capabilitySnapshot(namespace, user string, rule snapshot.PolicyRule) snapshot.Snapshot {
	value := baseSnapshot()
	roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: namespace, Name: "test-" + user}
	value.Identities = []snapshot.Identity{{Kind: snapshot.IdentityUser, Name: user}}
	value.Roles = []snapshot.Role{{Ref: roleRef, Rules: []snapshot.PolicyRule{rule}}}
	value.Bindings = []snapshot.Binding{{
		Ref:     snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: namespace, Name: "test-" + user},
		RoleRef: roleRef, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: user}},
	}}
	return value
}

func tokenSnapshot(namespace, user string) snapshot.Snapshot {
	value := capabilitySnapshot(namespace, user, snapshot.PolicyRule{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"admin"}})
	value.ServiceAccounts = []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: namespace, Name: "admin"}}}
	return value
}

func secretSnapshot() snapshot.Snapshot {
	value := capabilitySnapshot("prod", "alice", snapshot.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}})
	value.Assets = []snapshot.Asset{{Ref: snapshot.ObjectRef{Kind: "Secret", Namespace: "prod", Name: "database"}, AssetType: "Secret"}}
	return value
}

func clusterAdminSnapshot() snapshot.Snapshot {
	value := baseSnapshot()
	roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}
	value.Identities = []snapshot.Identity{{Kind: snapshot.IdentityUser, Name: "alice"}}
	value.Roles = []snapshot.Role{{Ref: roleRef, Rules: []snapshot.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}}}}
	value.Bindings = []snapshot.Binding{{
		Ref:     snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "admins"},
		RoleRef: roleRef, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
	}}
	return value
}
