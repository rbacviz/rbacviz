package permission_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const rbacGroup = "rbac.authorization.k8s.io"

func TestRoleBindingResolvesRoleAndClusterRoleWithinNamespace(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{
		role("Role", "prod", "pod-reader", rule([]string{"get"}, []string{""}, []string{"pods"}, nil, nil)),
		role("ClusterRole", "", "deployment-reader", rule([]string{"list"}, []string{"apps"}, []string{"deployments"}, nil, nil)),
	}
	value.Bindings = []snapshot.Binding{
		binding("RoleBinding", "prod", "pods", "Role", "prod", "pod-reader", user("alice")),
		binding("RoleBinding", "prod", "deployments", "ClusterRole", "", "deployment-reader", user("alice")),
	}
	resolver := mustResolver(t, value)
	result := resolver.Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil)
	if len(result.Capabilities) != 2 {
		t.Fatalf("capabilities = %d, want 2: %#v", len(result.Capabilities), result.Capabilities)
	}
	for _, capability := range result.Capabilities {
		if capability.Scope != permission.ScopeNamespaced || capability.Namespace != "prod" {
			t.Fatalf("scope = %s namespace = %q, want Namespaced/prod", capability.Scope, capability.Namespace)
		}
	}
}

func TestClusterRoleBindingUsesDiscoveredResourceScope(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{role("ClusterRole", "", "mixed", rule([]string{"get"}, []string{""}, []string{"pods", "nodes"}, nil, nil))}
	value.Bindings = []snapshot.Binding{binding("ClusterRoleBinding", "", "mixed", "ClusterRole", "", "mixed", serviceAccount("prod", "api"))}
	result := mustResolver(t, value).Permissions(permission.Identity{Kind: snapshot.IdentityServiceAccount, Namespace: "prod", Name: "api"}, nil)
	if len(result.Capabilities) != 2 {
		t.Fatalf("capabilities = %d, want 2", len(result.Capabilities))
	}
	scopes := map[string]permission.Scope{}
	for _, capability := range result.Capabilities {
		scopes[capability.Resource] = capability.Scope
	}
	if scopes["pods"] != permission.ScopeNamespaced || scopes["nodes"] != permission.ScopeCluster {
		t.Fatalf("scopes = %#v, want pods Namespaced and nodes Cluster", scopes)
	}
}

func TestExplicitGroupsAddGrantsWithoutInferringMembership(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{role("ClusterRole", "", "reader", rule([]string{"get"}, []string{""}, []string{"pods"}, nil, nil))}
	value.Bindings = []snapshot.Binding{binding("ClusterRoleBinding", "", "readers", "ClusterRole", "", "reader", group("developers"))}
	resolver := mustResolver(t, value)
	without := resolver.Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil)
	if len(without.Capabilities) != 0 {
		t.Fatalf("group membership was inferred: %#v", without.Capabilities)
	}
	with := resolver.Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, []string{"developers"})
	if len(with.Capabilities) != 1 || with.Capabilities[0].Grants[0].Subject.Kind != snapshot.IdentityGroup {
		t.Fatalf("explicit group grant missing: %#v", with.Capabilities)
	}
}

func TestWildcardsSubresourcesResourceNamesAndNonResourceURLs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		capability permission.Capability
		action     permission.Action
		want       bool
	}{
		{name: "wildcards", capability: permission.Capability{Verb: "*", APIGroup: "*", Resource: "*", Scope: permission.ScopeUnknown}, action: permission.Action{Verb: "patch", APIGroup: "apps", Resource: "deployments", Namespace: "prod"}, want: true},
		{name: "named object", capability: permission.Capability{Verb: "get", Resource: "pods", ResourceNames: []string{"api"}, Scope: permission.ScopeNamespaced, Namespace: "prod"}, action: permission.Action{Verb: "get", Resource: "pods", Namespace: "prod", ResourceName: "api"}, want: true},
		{name: "named rule rejects collection", capability: permission.Capability{Verb: "get", Resource: "pods", ResourceNames: []string{"api"}, Scope: permission.ScopeNamespaced, Namespace: "prod"}, action: permission.Action{Verb: "get", Resource: "pods", Namespace: "prod"}, want: false},
		{name: "subresource exact", capability: permission.Capability{Verb: "get", Resource: "pods", Subresource: "log", Scope: permission.ScopeNamespaced, Namespace: "prod"}, action: permission.Action{Verb: "get", Resource: "pods", Subresource: "log", Namespace: "prod"}, want: true},
		{name: "subresource differs", capability: permission.Capability{Verb: "get", Resource: "pods", Subresource: "log", Scope: permission.ScopeNamespaced, Namespace: "prod"}, action: permission.Action{Verb: "get", Resource: "pods", Subresource: "exec", Namespace: "prod"}, want: false},
		{name: "non-resource prefix", capability: permission.Capability{Verb: "get", NonResourceURL: "/apis/*", Scope: permission.ScopeNonResource}, action: permission.Action{Verb: "get", NonResourceURL: "/apis/apps/v1"}, want: true},
		{name: "non-resource prefix boundary is literal", capability: permission.Capability{Verb: "get", NonResourceURL: "/healthz", Scope: permission.ScopeNonResource}, action: permission.Action{Verb: "get", NonResourceURL: "/healthz/ready"}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := permission.Allows(test.capability, test.action); got != test.want {
				t.Fatalf("Allows() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDuplicateCapabilitiesRetainIndependentGrants(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{
		role("Role", "prod", "reader-one", rule([]string{"get"}, []string{""}, []string{"pods"}, nil, nil)),
		role("Role", "prod", "reader-two", rule([]string{"get"}, []string{""}, []string{"pods"}, nil, nil)),
	}
	value.Bindings = []snapshot.Binding{
		binding("RoleBinding", "prod", "one", "Role", "prod", "reader-one", user("alice")),
		binding("RoleBinding", "prod", "two", "Role", "prod", "reader-two", user("alice")),
	}
	result := mustResolver(t, value).WhyCan(
		permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil,
		permission.Action{Verb: "get", Resource: "pods", Namespace: "prod"},
	)
	if !result.Allowed || len(result.Capabilities) != 1 || len(result.Capabilities[0].Grants) != 2 {
		t.Fatalf("redundant grants were not retained: %#v", result)
	}
	if result.Capabilities[0].Grants[0].ID == result.Capabilities[0].Grants[1].ID {
		t.Fatal("independent grants have the same ID")
	}
}

func TestAggregatedClusterRoleRetainsChainAndIgnoresMaterializedRules(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	leaf := role("ClusterRole", "", "leaf", rule([]string{"get"}, []string{""}, []string{"secrets"}, nil, nil))
	leaf.Labels = []snapshot.KeyValue{{Key: "rbacviz.io/aggregate", Value: "true"}}
	aggregate := role("ClusterRole", "", "aggregate", rule([]string{"delete"}, []string{""}, []string{"nodes"}, nil, nil))
	aggregate.AggregationSelectors = []snapshot.LabelSelector{{MatchLabels: []snapshot.KeyValue{{Key: "rbacviz.io/aggregate", Value: "true"}}}}
	value.Roles = []snapshot.Role{aggregate, leaf}
	value.Bindings = []snapshot.Binding{binding("ClusterRoleBinding", "", "aggregate", "ClusterRole", "", "aggregate", user("alice"))}
	result := mustResolver(t, value).Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil)
	if len(result.Capabilities) != 1 || result.Capabilities[0].Resource != "secrets" {
		t.Fatalf("aggregate capabilities = %#v, want only derived secrets rule", result.Capabilities)
	}
	grant := result.Capabilities[0].Grants[0]
	if grant.SourceRoleRef.Name != "leaf" || len(grant.AggregationChain) != 2 || grant.AggregationChain[0].Name != "aggregate" || grant.AggregationChain[1].Name != "leaf" {
		t.Fatalf("aggregation provenance = %#v", grant)
	}
}

func TestAggregationCycleAndMissingRoleReferenceBecomeWarnings(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	left := role("ClusterRole", "", "left")
	left.Labels = []snapshot.KeyValue{{Key: "side", Value: "left"}}
	left.AggregationSelectors = []snapshot.LabelSelector{{MatchLabels: []snapshot.KeyValue{{Key: "side", Value: "right"}}}}
	right := role("ClusterRole", "", "right")
	right.Labels = []snapshot.KeyValue{{Key: "side", Value: "right"}}
	right.AggregationSelectors = []snapshot.LabelSelector{{MatchLabels: []snapshot.KeyValue{{Key: "side", Value: "left"}}}}
	value.Roles = []snapshot.Role{left, right}
	value.Bindings = []snapshot.Binding{binding("RoleBinding", "prod", "missing", "Role", "prod", "does-not-exist", user("alice"))}
	result := mustResolver(t, value).Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil)
	if result.Complete {
		t.Fatal("result with resolver warnings is complete")
	}
	codes := warningCodes(result.Warnings)
	if !slices.Contains(codes, "AggregationCycle") || !slices.Contains(codes, "MissingRoleReference") {
		t.Fatalf("warning codes = %v", codes)
	}
}

func TestUnknownDiscoveryScopeRemainsMatchableAndWarned(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{role("ClusterRole", "", "widgets", rule([]string{"get"}, []string{"example.io"}, []string{"widgets"}, nil, nil))}
	value.Bindings = []snapshot.Binding{binding("ClusterRoleBinding", "", "widgets", "ClusterRole", "", "widgets", user("alice"))}
	result := mustResolver(t, value).WhyCan(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil, permission.Action{Verb: "get", APIGroup: "example.io", Resource: "widgets", Namespace: "prod"})
	if !result.Allowed || result.Complete || len(result.Capabilities) != 1 || result.Capabilities[0].Scope != permission.ScopeUnknown {
		t.Fatalf("unknown scope result = %#v", result)
	}
	if !slices.Contains(warningCodes(result.Warnings), "UnknownResourceScope") {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
}

func TestWhoCanReturnsGroupsAsGroups(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{role("ClusterRole", "", "reader", rule([]string{"get"}, []string{""}, []string{"pods"}, nil, nil))}
	value.Bindings = []snapshot.Binding{
		binding("ClusterRoleBinding", "", "users", "ClusterRole", "", "reader", user("alice")),
		binding("ClusterRoleBinding", "", "groups", "ClusterRole", "", "reader", group("developers")),
	}
	result := mustResolver(t, value).WhoCan(permission.Action{Verb: "get", Resource: "pods", Namespace: "prod"})
	if len(result.Subjects) != 2 || result.Subjects[0].Identity.Kind != snapshot.IdentityGroup || result.Subjects[1].Identity.Kind != snapshot.IdentityUser {
		t.Fatalf("subjects = %#v", result.Subjects)
	}
}

func TestResolutionIsDeterministic(t *testing.T) {
	t.Parallel()
	value := baseSnapshot()
	value.Roles = []snapshot.Role{
		role("Role", "prod", "z", rule([]string{"list", "get"}, []string{""}, []string{"pods"}, nil, nil)),
		role("Role", "prod", "a", rule([]string{"watch"}, []string{""}, []string{"pods"}, nil, nil)),
	}
	value.Bindings = []snapshot.Binding{
		binding("RoleBinding", "prod", "z", "Role", "prod", "z", user("alice")),
		binding("RoleBinding", "prod", "a", "Role", "prod", "a", user("alice")),
	}
	forward := mustResolver(t, value).Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil)
	slices.Reverse(value.Roles)
	slices.Reverse(value.Bindings)
	reverse := mustResolver(t, value).Permissions(permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, nil)
	left, _ := json.Marshal(forward)
	right, _ := json.Marshal(reverse)
	if string(left) != string(right) {
		t.Fatalf("resolution is not deterministic:\n%s\n%s", left, right)
	}
}

func FuzzParseIdentity(f *testing.F) {
	for _, seed := range []string{"user:alice", "group:developers", "serviceaccount:prod:api", "", "sa:x:y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		_, _ = permission.ParseIdentity(value)
	})
}

func FuzzAllows(f *testing.F) {
	f.Add("get", "pods", "", "prod", "get", "pods", "", "prod")
	f.Add("*", "*", "", "", "patch", "deployments", "status", "prod")
	f.Fuzz(func(t *testing.T, ruleVerb, ruleResource, ruleSubresource, ruleNamespace, verb, resource, subresource, namespace string) {
		if len(strings.Join([]string{ruleVerb, ruleResource, ruleSubresource, ruleNamespace, verb, resource, subresource, namespace}, "")) > 8192 {
			t.Skip()
		}
		_ = permission.Allows(
			permission.Capability{Verb: ruleVerb, Resource: ruleResource, Subresource: ruleSubresource, Namespace: ruleNamespace, Scope: permission.ScopeNamespaced},
			permission.Action{Verb: verb, Resource: resource, Subresource: subresource, Namespace: namespace},
		)
	})
}

func BenchmarkPermissions(b *testing.B) {
	value := baseSnapshot()
	for index := 0; index < 100; index++ {
		name := "reader-" + strings.Repeat("x", index%8) + string(rune('a'+index%26))
		value.Roles = append(value.Roles, role("Role", "prod", name, rule([]string{"get", "list", "watch"}, []string{""}, []string{"pods", "configmaps"}, nil, nil)))
		value.Bindings = append(value.Bindings, binding("RoleBinding", "prod", name, "Role", "prod", name, user("alice")))
	}
	resolver := mustResolver(b, value)
	identity := permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}
	b.ReportAllocs()
	for range b.N {
		_ = resolver.Permissions(identity, nil)
	}
}

func baseSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources: []snapshot.APIResource{
			{GroupVersion: "v1", Version: "v1", Name: "nodes", Kind: "Node", Verbs: []string{"get"}},
			{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "list"}},
			{GroupVersion: "v1", Version: "v1", Name: "pods/log", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}},
			{GroupVersion: "v1", Version: "v1", Name: "secrets", Kind: "Secret", Namespaced: true, Verbs: []string{"get"}},
			{GroupVersion: "apps/v1", APIGroup: "apps", Version: "v1", Name: "deployments", Kind: "Deployment", Namespaced: true, Verbs: []string{"get", "list"}},
		},
	}
}

func role(kind, namespace, name string, rules ...snapshot.PolicyRule) snapshot.Role {
	return snapshot.Role{Ref: snapshot.ObjectRef{APIGroup: rbacGroup, Kind: kind, Namespace: namespace, Name: name}, Rules: rules}
}

func rule(verbs, groups, resources, names, urls []string) snapshot.PolicyRule {
	return snapshot.PolicyRule{Verbs: verbs, APIGroups: groups, Resources: resources, ResourceNames: names, NonResourceURLs: urls}
}

func binding(kind, namespace, name, roleKind, roleNamespace, roleName string, subjects ...snapshot.Subject) snapshot.Binding {
	return snapshot.Binding{
		Ref:     snapshot.ObjectRef{APIGroup: rbacGroup, Kind: kind, Namespace: namespace, Name: name},
		RoleRef: snapshot.ObjectRef{APIGroup: rbacGroup, Kind: roleKind, Namespace: roleNamespace, Name: roleName}, Subjects: subjects,
	}
}

func user(name string) snapshot.Subject {
	return snapshot.Subject{Kind: snapshot.IdentityUser, APIGroup: rbacGroup, Name: name}
}
func group(name string) snapshot.Subject {
	return snapshot.Subject{Kind: snapshot.IdentityGroup, APIGroup: rbacGroup, Name: name}
}
func serviceAccount(namespace, name string) snapshot.Subject {
	return snapshot.Subject{Kind: snapshot.IdentityServiceAccount, Namespace: namespace, Name: name}
}

func mustResolver(tb testing.TB, value snapshot.Snapshot) *permission.Resolver {
	tb.Helper()
	resolver, err := permission.New(value)
	if err != nil {
		tb.Fatalf("permission.New() error = %v", err)
	}
	return resolver
}

func warningCodes(values []permission.Warning) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Code)
	}
	return result
}
