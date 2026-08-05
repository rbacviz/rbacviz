package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/config"
	"github.com/rbacviz/rbacviz/internal/remediation"
	"github.com/rbacviz/rbacviz/internal/snapshot"
	"github.com/rbacviz/rbacviz/internal/version"
)

func TestRemediateCommandHumanAndJSONAreOffline(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	file := directory + "/snapshot.json"
	if err := snapshot.Save(file, remediationCLISnapshot()); err != nil {
		t.Fatal(err)
	}
	called := false
	dependencies := Dependencies{Version: version.Info{Version: "test"}, LookupEnv: func(string) (string, bool) { return "", false }, UserConfigDir: func() (string, error) { return directory, nil }, CollectSnapshot: func(context.Context, config.Config, string) (snapshot.Snapshot, error) {
		called = true
		return snapshot.Snapshot{}, nil
	}}
	streams := func() (IOStreams, *bytes.Buffer, *bytes.Buffer) {
		out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
		return IOStreams{In: strings.NewReader(""), Out: out, ErrOut: errOut}, out, errOut
	}
	ioStreams, out, errOut := streams()
	code := Execute(context.Background(), []string{"--snapshot", file, "remediate", "--top", "3"}, ioStreams, dependencies)
	if code != 0 || errOut.String() != "" || !strings.Contains(out.String(), "recommended=") || !strings.Contains(out.String(), "permissions lost:") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	ioStreams, out, errOut = streams()
	code = Execute(context.Background(), []string{"--snapshot", file, "--output", "json", "remediate"}, ioStreams, dependencies)
	if code != 0 || errOut.String() != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	var result remediation.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != remediation.ResultSchemaVersion || result.Summary.Recommended == 0 {
		t.Fatalf("result = %+v", result.Summary)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Diff != nil || result.Summary.Dominated != 1 {
		t.Fatalf("default candidate filtering = candidates:%d summary:%+v", len(result.Candidates), result.Summary)
	}
	if called {
		t.Fatal("offline remediation unexpectedly called live collector")
	}
}

func TestRemediateCommandValidatesBounds(t *testing.T) {
	t.Parallel()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	code := Execute(context.Background(), []string{"remediate", "--max-candidates", "0"}, IOStreams{In: strings.NewReader(""), Out: out, ErrOut: errOut}, Dependencies{})
	if code == 0 || !strings.Contains(errOut.String(), "max-candidates") {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func remediationCLISnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test", Metadata: snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources:    []snapshot.APIResource{{GroupVersion: "v1", Version: "v1", Name: "serviceaccounts", Kind: "ServiceAccount", Namespaced: true}},
		ServiceAccounts: []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "admin"}}},
		Roles:           []snapshot.Role{{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "minter"}, Rules: []snapshot.PolicyRule{{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{"admin"}}}}},
		Bindings:        []snapshot.Binding{{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "minters"}, RoleRef: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "minter"}, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}}}},
	}
}
