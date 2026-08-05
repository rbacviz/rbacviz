package diff

import "testing"

func FuzzDangerousCategory(f *testing.F) {
	f.Add("*", "*", "*")
	f.Add("get", "", "secrets")
	f.Add("patch", "apps", "deployments")
	f.Fuzz(func(t *testing.T, verb, group, resource string) {
		first := dangerousCategory(Capability{Verb: verb, APIGroup: group, Resource: resource})
		second := dangerousCategory(Capability{Verb: verb, APIGroup: group, Resource: resource})
		if first != second {
			t.Fatalf("category is nondeterministic: %q != %q", first, second)
		}
	})
}
