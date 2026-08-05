package attackpath

import (
	"context"
	"reflect"
	"testing"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func FuzzDeterministicAnalysis(f *testing.F) {
	f.Add(uint8(10), uint16(100))
	f.Fuzz(func(t *testing.T, topRaw uint8, maxRaw uint16) {
		top := int(topRaw%100) + 1
		maxExpanded := int(maxRaw%1000) + 1
		value := capabilitySnapshot("alice", snapshot.PolicyRule{Verbs: []string{"get", "create"}, APIGroups: []string{""}, Resources: []string{"secrets", "pods"}})
		engine, err := New(value)
		if err != nil {
			t.Fatal(err)
		}
		query := Query{Top: top, MaxExpanded: maxExpanded}
		first, err := engine.Analyze(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		second, err := engine.Analyze(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("analysis is not deterministic")
		}
	})
}

func BenchmarkAnalyzeAttackPaths(b *testing.B) {
	value := baseSnapshot()
	for index := 0; index < 100; index++ {
		user := "user-" + string(rune('a'+index%26)) + string(rune('a'+index/26))
		roleRef := snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: user}
		value.Identities = append(value.Identities, snapshot.Identity{Kind: snapshot.IdentityUser, Name: user})
		value.Roles = append(value.Roles, snapshot.Role{Ref: roleRef, Rules: []snapshot.PolicyRule{{Verbs: []string{"get", "create"}, APIGroups: []string{""}, Resources: []string{"secrets", "pods"}}}})
		value.Bindings = append(value.Bindings, snapshot.Binding{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: user}, RoleRef: roleRef, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: user}}})
	}
	engine, err := New(value)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := engine.Analyze(context.Background(), Query{Top: 10, MaxExpanded: 50000}); err != nil {
			b.Fatal(err)
		}
	}
}
