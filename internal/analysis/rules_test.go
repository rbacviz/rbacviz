package analysis

import (
	"context"
	"testing"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestEveryCapabilityRuleMatchesItsRepresentativePermission(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ruleID     string
		capability permission.Capability
	}{
		{"RBACVIZ-R004", testCapability("*", "", "pods", "")},
		{"RBACVIZ-R005", testCapability("get", "", "*", "")},
		{"RBACVIZ-R006", testCapability("get", "*", "pods", "")},
		{"RBACVIZ-R007", testCapability("get", "", "secrets", "")},
		{"RBACVIZ-R008", testCapability("patch", "", "secrets", "")},
		{"RBACVIZ-R009", testCapability("create", "", "serviceaccounts", "token")},
		{"RBACVIZ-R010", testCapability("create", "", "pods", "")},
		{"RBACVIZ-R011", testCapability("patch", "apps", "deployments", "")},
		{"RBACVIZ-R012", testCapability("create", "", "pods", "exec")},
		{"RBACVIZ-R013", testCapability("create", "", "pods", "attach")},
		{"RBACVIZ-R014", testCapability("create", "", "pods", "portforward")},
		{"RBACVIZ-R015", testCapability("get", "", "nodes", "proxy")},
		{"RBACVIZ-R016", testCapability("get", "", "services", "proxy")},
		{"RBACVIZ-R017", testCapability("impersonate", "", "users", "")},
		{"RBACVIZ-R018", testCapability("impersonate", "", "groups", "")},
		{"RBACVIZ-R019", testCapability("impersonate", "", "serviceaccounts", "")},
		{"RBACVIZ-R020", testCapability("update", "rbac.authorization.k8s.io", "roles", "")},
		{"RBACVIZ-R021", testCapability("update", "rbac.authorization.k8s.io", "clusterroles", "")},
		{"RBACVIZ-R022", testCapability("create", "rbac.authorization.k8s.io", "rolebindings", "")},
		{"RBACVIZ-R023", testCapability("create", "rbac.authorization.k8s.io", "clusterrolebindings", "")},
		{"RBACVIZ-R024", testCapability("bind", "rbac.authorization.k8s.io", "clusterroles", "")},
		{"RBACVIZ-R025", testCapability("escalate", "rbac.authorization.k8s.io", "roles", "")},
		{"RBACVIZ-R026", testCapability("update", "certificates.k8s.io", "certificatesigningrequests", "approval")},
		{"RBACVIZ-R027", testCapability("patch", "admissionregistration.k8s.io", "validatingwebhookconfigurations", "")},
	}
	rules := rulesByID(BuiltinRules())
	for _, test := range tests {
		t.Run(test.ruleID, func(t *testing.T) {
			t.Parallel()
			values, err := rules[test.ruleID].Evaluate(context.Background(), EvaluationContext{Subjects: []SubjectPermissions{{Identity: permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, Capabilities: []permission.Capability{test.capability}}}})
			if err != nil || len(values) != 1 {
				t.Fatalf("Evaluate() findings = %d error = %v", len(values), err)
			}
		})
	}
}

func TestCapabilityRulesRejectNearbyBenignPermissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ruleID     string
		capability permission.Capability
	}{
		{"RBACVIZ-R007", testCapability("get", "", "configmaps", "")},
		{"RBACVIZ-R012", testCapability("get", "", "pods", "log")},
		{"RBACVIZ-R024", testCapability("get", "rbac.authorization.k8s.io", "clusterroles", "")},
		{"RBACVIZ-R026", testCapability("get", "certificates.k8s.io", "certificatesigningrequests", "")},
	}
	rules := rulesByID(BuiltinRules())
	for _, test := range tests {
		values, err := rules[test.ruleID].Evaluate(context.Background(), EvaluationContext{Subjects: []SubjectPermissions{{Identity: permission.Identity{Kind: snapshot.IdentityUser, Name: "alice"}, Capabilities: []permission.Capability{test.capability}}}})
		if err != nil || len(values) != 0 {
			t.Errorf("%s matched benign capability: findings=%d error=%v", test.ruleID, len(values), err)
		}
	}
}

func TestEveryWorkloadRuleMatchesItsObservedField(t *testing.T) {
	t.Parallel()
	workload := snapshot.Workload{
		Ref:                  snapshot.ObjectRef{Kind: "Pod", Namespace: "prod", Name: "danger"},
		PrivilegedContainers: []string{"app"}, HostNetwork: true, HostPID: true, HostIPC: true,
		Volumes: []snapshot.VolumeReference{{Name: "host", Kind: "HostPath", Target: "/var/lib"}},
	}
	rules := rulesByID(BuiltinRules())
	for _, ruleID := range []string{"RBACVIZ-R028", "RBACVIZ-R029", "RBACVIZ-R030", "RBACVIZ-R031", "RBACVIZ-R032"} {
		values, err := rules[ruleID].Evaluate(context.Background(), EvaluationContext{Snapshot: snapshot.Snapshot{Workloads: []snapshot.Workload{workload}}})
		if err != nil || len(values) != 1 {
			t.Errorf("%s findings=%d error=%v", ruleID, len(values), err)
		}
	}
}

func testCapability(verb, group, resource, subresource string) permission.Capability {
	return permission.Capability{Verb: verb, APIGroup: group, Resource: resource, Subresource: subresource, Scope: permission.ScopeUnknown, ResourceNames: []string{}, Grants: []permission.GrantEvidence{}}
}

func rulesByID(rules []Rule) map[string]Rule {
	result := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		result[rule.Metadata().ID] = rule
	}
	return result
}
