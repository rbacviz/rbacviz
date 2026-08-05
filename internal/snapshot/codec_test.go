package snapshot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestCanonicalRoundTripIsDeterministic(t *testing.T) {
	t.Parallel()
	value := fixture()
	first, err := snapshot.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	loaded, err := snapshot.Unmarshal(first)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	second, err := snapshot.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal(round trip) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical JSON changed after round trip\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if bytes.Contains(first, []byte(`: null`)) {
		t.Fatalf("canonical JSON contains null slice: %s", first)
	}
	if got := loaded.Roles[0].Rules[0].Verbs; len(got) != 2 || got[0] != "get" || got[1] != "list" {
		t.Fatalf("verbs = %v, want sorted unique values", got)
	}
	if len(loaded.Identities) != 2 {
		t.Fatalf("identities = %d, want user plus service account", len(loaded.Identities))
	}
}

func TestSaveLoadAndSemanticDigest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cluster.json")
	value := fixture()
	if err := snapshot.Save(path, value); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := snapshot.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	digestA, err := snapshot.SemanticDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Metadata.CollectedAt = "2027-01-01T00:00:00Z"
	loaded.Metadata.Context = "another-context"
	digestB, err := snapshot.SemanticDigest(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestB {
		t.Fatalf("semantic digest changed with provenance: %s != %s", digestA, digestB)
	}
}

func TestUnmarshalRejectsSensitiveFieldsAndUnknownMajor(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- these are intentionally fake values used to test rejection.
	for name, data := range map[string]string{
		"secret data":   `{"schemaVersion":"1.0","data":{"password":"value"}}`,
		"bearer token":  `{"schemaVersion":"1.0","metadata":{"bearerToken":"value"}}`,
		"unknown major": `{"schemaVersion":"2.0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := snapshot.Unmarshal([]byte(data)); err == nil {
				t.Fatal("Unmarshal() error = nil")
			}
		})
	}
}

func TestUnmarshalToleratesAdditiveV1Fields(t *testing.T) {
	t.Parallel()
	data, err := snapshot.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := strings.Replace(string(data), `"toolVersion": "test",`, `"toolVersion": "test", "futureField": true,`, 1)
	if _, err := snapshot.Unmarshal([]byte(withUnknown)); err != nil {
		t.Fatalf("Unmarshal(additive field) error = %v", err)
	}
}

func FuzzUnmarshal(f *testing.F) {
	data, err := snapshot.Marshal(fixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schemaVersion":"1.0"}`))
	f.Add([]byte(`{"schemaVersion":"1.0","data":"forbidden"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _ = snapshot.Unmarshal(input)
	})
}

func BenchmarkMarshal(b *testing.B) {
	value := fixture()
	b.ReportAllocs()
	for range b.N {
		if _, err := snapshot.Marshal(value); err != nil {
			b.Fatal(err)
		}
	}
}

func fixture() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", Context: "dev", Complete: true},
		Roles: []snapshot.Role{{
			Ref:    snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
			Labels: []snapshot.KeyValue{{Key: "z", Value: "2"}, {Key: "a", Value: "1"}},
			Rules:  []snapshot.PolicyRule{{Verbs: []string{"list", "get", "get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		}},
		Bindings: []snapshot.Binding{{
			Ref:      snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "readers"},
			RoleRef:  snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"},
			Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}},
		}},
		ServiceAccounts: []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "app"}}},
	}
}
