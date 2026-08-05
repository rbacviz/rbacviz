package attackpath

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestDirectClusterAdminPathIsStableAndEvidenceBacked(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Identities = []snapshot.Identity{{Kind: snapshot.IdentityUser, Name: "dave"}}
	value.Roles = []snapshot.Role{{Ref: clusterRoleRef("cluster-admin"), Rules: []snapshot.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}}}}
	value.Bindings = []snapshot.Binding{{
		Ref:     snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "admins"},
		RoleRef: clusterRoleRef("cluster-admin"), Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "dave"}},
	}}
	target := TargetClusterAdmin
	first := analyze(t, value, Query{To: &target, Top: 10})
	if len(first.Paths) != 1 {
		t.Fatalf("paths = %d, want 1: %#v", len(first.Paths), first.Paths)
	}
	path := first.Paths[0]
	if path.TemplateID != "RBACVIZ-AP001" || path.Confidence != ConfidenceConfirmed || path.Blocked || len(path.Steps) != 2 {
		t.Fatalf("unexpected direct path: %#v", path)
	}
	if len(path.Steps[0].Evidence) < 2 || path.Steps[0].Evidence[0].Grant == nil {
		t.Fatalf("binding provenance is missing: %#v", path.Steps[0].Evidence)
	}

	value.Metadata.CollectedAt = "2030-01-01T00:00:00Z"
	value.Bindings[0].Subjects = append([]snapshot.Subject(nil), value.Bindings[0].Subjects...)
	second := analyze(t, value, Query{To: &target, Top: 10})
	if first.Paths[0].ID != second.Paths[0].ID {
		t.Fatalf("path ID changed with collection metadata: %s != %s", first.Paths[0].ID, second.Paths[0].ID)
	}
}

func TestSystemMastersPathRepresentsOnlyTheObservedGroup(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Identities = []snapshot.Identity{{Kind: snapshot.IdentityGroup, Name: "system:masters"}}
	roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"}
	value.Roles = []snapshot.Role{{Ref: roleRef, Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}}}}
	value.Bindings = []snapshot.Binding{{
		Ref:     snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "masters-observed"},
		RoleRef: roleRef, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityGroup, Name: "system:masters"}},
	}}
	target := TargetSystemMasters
	path := pathByTemplate(t, analyze(t, value, Query{To: &target, Top: 10}).Paths, "RBACVIZ-AP002")
	if path.Source.Kind != snapshot.IdentityGroup || path.Source.Name != "system:masters" {
		t.Fatalf("group membership was invented: %#v", path.Source)
	}
}

func TestServiceAccountTokenPathHasExactGrantAndTarget(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"admin"}})
	value.ServiceAccounts = []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "admin"}}}
	target := TargetServiceAccountTakeover
	result := analyze(t, value, Query{To: &target, Top: 10})
	path := pathByTemplate(t, result.Paths, "RBACVIZ-AP003")
	if path.Target.Key != "privilege-target:service_account_takeover:prod:admin" || path.Confidence != ConfidenceLikely {
		t.Fatalf("unexpected token path target/confidence: %#v", path)
	}
	step := path.Steps[0]
	if step.Evidence[0].Permission == nil || step.Evidence[0].Permission.Subresource != "token" || step.Evidence[1].Grant == nil || step.Evidence[1].Grant.PolicyRuleID == "" {
		t.Fatalf("exact permission/grant evidence missing: %#v", step.Evidence)
	}
	if step.Prerequisites[0].State != PrerequisiteSatisfied {
		t.Fatalf("target ServiceAccount should be observed: %#v", step.Prerequisites)
	}
}

func TestSecretPathNeverClaimsCredentialContents(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}})
	value.Assets = []snapshot.Asset{{Ref: snapshot.ObjectRef{Kind: "Secret", Namespace: "prod", Name: "database"}, AssetType: "Secret"}}
	target := TargetSecretAccess
	path := pathByTemplate(t, analyze(t, value, Query{To: &target, Top: 10}).Paths, "RBACVIZ-AP005")
	if path.Confidence != ConfidenceConditional || path.Steps[0].Prerequisites[0].State != PrerequisiteRequired {
		t.Fatalf("Secret inference must remain conditional: %#v", path)
	}
	if path.Steps[0].Prerequisites[0].Evidence != "Secret values are intentionally not collected" {
		t.Fatalf("missing Secret safety explanation: %#v", path.Steps[0].Prerequisites)
	}
}

func TestRestrictedPSABlocksHostEscapeOnlyInItsNamespace(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"pods"}})
	value.Assets = []snapshot.Asset{{Ref: snapshot.ObjectRef{Kind: "Node", Name: "worker-1"}, AssetType: "Node"}}
	value.SecurityControls = []snapshot.SecurityControl{
		{Ref: snapshot.ObjectRef{Kind: "Namespace", Name: "dev"}, ControlType: "PodSecurityAdmission", Mode: "restricted"},
		{Ref: snapshot.ObjectRef{Kind: "Namespace", Name: "prod"}, ControlType: "PodSecurityAdmission", Mode: "restricted"},
	}
	target := TargetHostEscape
	path := pathByTemplate(t, analyze(t, value, Query{To: &target, Top: 10}).Paths, "RBACVIZ-AP012")
	if !path.Blocked || path.Confidence != ConfidenceBlocked || path.Cost < 1000 {
		t.Fatalf("restricted PSA must retain a blocked path: %#v", path)
	}
	controls := path.Steps[0].MitigatingControls
	if len(controls) != 1 || controls[0].Ref.Name != "prod" || controls[0].State != MitigationBlocking || !controls[0].SemanticsKnown {
		t.Fatalf("namespace-specific PSA evaluation is wrong: %#v", controls)
	}
}

func TestUnknownAdmissionControlLowersBindingMutationConfidence(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"create"}, APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings"}})
	value.SecurityControls = []snapshot.SecurityControl{{
		Ref:         snapshot.ObjectRef{APIGroup: "admissionregistration.k8s.io", Kind: "ValidatingWebhookConfiguration", Name: "policy"},
		ControlType: "ValidatingWebhook", SemanticsUnknown: true,
	}}
	target := TargetRBACControl
	path := pathByTemplate(t, analyze(t, value, Query{To: &target, Top: 10}).Paths, "RBACVIZ-AP008")
	if path.Confidence != ConfidenceUnknown || len(path.Steps[0].MitigatingControls) != 1 || path.Steps[0].MitigatingControls[0].State != MitigationPotential {
		t.Fatalf("unknown admission semantics must be visible: %#v", path)
	}
}

func TestIncompleteCollectionLowersConfidenceAndIsNotAllClear(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes/proxy"}})
	value.Roles[0].Ref = clusterRoleRef("node-proxy")
	value.Bindings[0].Ref = snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRoleBinding", Name: "node-proxy"}
	value.Bindings[0].RoleRef = clusterRoleRef("node-proxy")
	value.Metadata.Complete = false
	value.Warnings = []snapshot.Warning{{Resource: "nodes", Code: "Forbidden", Message: "collection failed"}}
	target := TargetNodeControl
	result := analyze(t, value, Query{To: &target, Top: 10})
	path := pathByTemplate(t, result.Paths, "RBACVIZ-AP010")
	if result.Complete || len(result.Warnings) == 0 || path.Confidence != ConfidenceUnknown {
		t.Fatalf("partial collection was hidden: %#v", result)
	}
}

func TestQueryFiltersTopAndHardExpansionLimit(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"secrets"}})
	identity := value.Identities[0]
	from := permissionIdentity(identity)
	target := TargetSecretAccess
	result := analyze(t, value, Query{From: &from, To: &target, Namespace: "prod", Top: 1, MaxExpanded: 1})
	if len(result.Paths) != 1 || result.Expanded != 1 || !result.Truncated {
		t.Fatalf("hard bounds not enforced: %#v", result)
	}
}

func TestAnalyzeHonorsCancellation(t *testing.T) {
	t.Parallel()
	engine, err := New(capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Analyze(ctx, Query{}); err == nil {
		t.Fatal("Analyze() accepted a canceled context")
	}
}

func TestTemplateCatalogHasStableUniqueIDsAndTargets(t *testing.T) {
	t.Parallel()
	if len(templates) != 12 {
		t.Fatalf("templates = %d, want 12", len(templates))
	}
	seen := make(map[string]struct{})
	for _, template := range templates {
		if template.ID == "" || template.Target == "" || template.Title == "" || len(template.Remediations) == 0 {
			t.Fatalf("incomplete template: %#v", template)
		}
		if _, found := seen[template.ID]; found {
			t.Fatalf("duplicate template ID %s", template.ID)
		}
		seen[template.ID] = struct{}{}
	}
	ids := make([]string, 0, len(templates))
	for _, template := range templates {
		ids = append(ids, template.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("template catalog is not stable: %v", ids)
	}
}

func TestWildcardCapabilitySeedsSubresourceAndResourceTemplates(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}})
	value.ServiceAccounts = []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "admin"}}}
	result := analyze(t, value, Query{Top: 100})
	for _, templateID := range []string{"RBACVIZ-AP003", "RBACVIZ-AP004", "RBACVIZ-AP005", "RBACVIZ-AP006", "RBACVIZ-AP007", "RBACVIZ-AP008", "RBACVIZ-AP009", "RBACVIZ-AP010", "RBACVIZ-AP011", "RBACVIZ-AP012"} {
		pathByTemplate(t, result.Paths, templateID)
	}
}

func analyze(t *testing.T, value snapshot.Snapshot, query Query) Result {
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

func pathByTemplate(t *testing.T, paths []Path, templateID string) Path {
	t.Helper()
	for _, path := range paths {
		if path.TemplateID == templateID {
			return path
		}
	}
	t.Fatalf("template %s not found in %#v", templateID, paths)
	return Path{}
}

func baseSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true},
			{GroupVersion: "v1", Version: "v1", Name: "nodes", Kind: "Node", Namespaced: false},
			{GroupVersion: "rbac.authorization.k8s.io/v1", APIGroup: "rbac.authorization.k8s.io", Version: "v1", Name: "rolebindings", Kind: "RoleBinding", Namespaced: true},
		},
	}
}

func capabilitySnapshot(user string, rule snapshot.PolicyRule) snapshot.Snapshot {
	value := baseSnapshot()
	roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "test"}
	value.Identities = []snapshot.Identity{{Kind: snapshot.IdentityUser, Name: user}}
	value.Roles = []snapshot.Role{{Ref: roleRef, Rules: []snapshot.PolicyRule{rule}}}
	value.Bindings = []snapshot.Binding{{
		Ref:     snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "test"},
		RoleRef: roleRef, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: user}},
	}}
	return value
}

func clusterRoleRef(name string) snapshot.ObjectRef {
	return snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: name}
}

func permissionIdentity(value snapshot.Identity) permission.Identity {
	return permission.Identity{Kind: value.Kind, Namespace: value.Namespace, Name: value.Name}
}

func TestCanonicalPathOrderingIgnoresInputOrder(t *testing.T) {
	t.Parallel()
	value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"secrets"}})
	first := analyze(t, value, Query{Top: 10})
	value.Roles[0].Rules[0].Verbs[0], value.Roles[0].Rules[0].Verbs[1] = value.Roles[0].Rules[0].Verbs[1], value.Roles[0].Rules[0].Verbs[0]
	second := analyze(t, value, Query{Top: 10})
	firstIDs, secondIDs := pathIDs(first.Paths), pathIDs(second.Paths)
	if !reflect.DeepEqual(firstIDs, secondIDs) {
		t.Fatalf("IDs changed with input order: %v != %v", firstIDs, secondIDs)
	}
}

func pathIDs(values []Path) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.ID
	}
	return result
}
