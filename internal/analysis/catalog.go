package analysis

import (
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	rbacReference        = "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
	rbacGoodPractices    = "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"
	podSecurityStandards = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
)

// BuiltinRules returns a new, deterministically ordered copy of the initial
// high-value ruleset. Each rule can also be constructed and tested alone.
func BuiltinRules() []Rule {
	modify := verbIs("create", "update", "patch", "delete", "deletecollection")
	read := verbIs("get", "list", "watch")
	rules := []Rule{
		bindingRule{metadata: meta("RBACVIZ-R001", "Cluster-wide cluster-admin access", SeverityCritical, 98, "A ClusterRoleBinding grants cluster-admin", "The subject can administer essentially every Kubernetes API resource cluster-wide.", "Remove the binding or replace cluster-admin with a least-privilege role.", rbacGoodPractices), match: func(binding snapshot.Binding, _ snapshot.Subject) bool {
			return binding.Ref.Kind == "ClusterRoleBinding" && binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin"
		}},
		bindingRule{metadata: meta("RBACVIZ-R002", "Namespaced cluster-admin binding", SeverityHigh, 82, "A RoleBinding grants the cluster-admin ClusterRole within one namespace", "The subject receives the role's namespaced permissions throughout the binding namespace.", "Replace cluster-admin with a namespace-specific least-privilege role.", rbacGoodPractices), match: func(binding snapshot.Binding, _ snapshot.Subject) bool {
			return binding.Ref.Kind == "RoleBinding" && binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin"
		}},
		bindingRule{metadata: meta("RBACVIZ-R003", "system:masters group binding", SeverityCritical, 100, "The system:masters group is explicitly bound", "Members of system:masters bypass ordinary authorization checks through the privileged system group.", "Avoid system:masters membership and use auditable, least-privilege RBAC bindings.", rbacReference), match: func(_ snapshot.Binding, subject snapshot.Subject) bool {
			return subject.Kind == snapshot.IdentityGroup && subject.Name == "system:masters"
		}},
		capRule("RBACVIZ-R004", "Wildcard verbs", SeverityHigh, 80, "A rule grants every verb", "Future or uncommon operations are implicitly authorized.", "Replace '*' with the exact required verbs.", func(value permission.Capability) bool { return value.Verb == "*" }),
		capRule("RBACVIZ-R005", "Wildcard resources", SeverityHigh, 82, "A rule grants access to every resource", "Current and future API resources may become reachable.", "Replace '*' with the exact required resources and subresources.", func(value permission.Capability) bool { return value.Resource == "*" }),
		capRule("RBACVIZ-R006", "Wildcard API groups", SeverityHigh, 78, "A rule grants access across every API group", "Resources added by Kubernetes or extensions may become reachable.", "Replace '*' with the exact required API groups.", func(value permission.Capability) bool { return value.APIGroup == "*" }),
		capRule("RBACVIZ-R007", "Secret read access", SeverityHigh, 76, "An identity can read Secret metadata or values through the API", "Readable Secrets may expose workload, registry, or external-system credentials.", "Restrict Secret get/list/watch permissions and scope access by namespace and resource name.", all(read, resourceIs("", "secrets"))),
		capRule("RBACVIZ-R008", "Secret modification access", SeverityHigh, 79, "An identity can create or modify Secrets", "Secret mutation can alter credentials or inject data consumed by workloads.", "Limit Secret mutation to dedicated controllers and narrowly scoped automation identities.", all(modify, resourceIs("", "secrets"))),
		capRule("RBACVIZ-R009", "ServiceAccount token creation", SeverityCritical, 90, "An identity can create ServiceAccount token subresources", "The identity may request a token for an allowed ServiceAccount and assume its permissions.", "Restrict create on serviceaccounts/token and constrain which ServiceAccount names are addressable.", all(verbIs("create"), subresourceIs("", "serviceaccounts", "token"))),
		capRule("RBACVIZ-R010", "Pod creation", SeverityHigh, 72, "An identity can create Pods", "Pod creation can expose node, volume, Secret, or ServiceAccount attack primitives when controls permit them.", "Grant workload deployment through constrained controllers and enforce Pod Security controls.", all(verbIs("create"), resourceIs("", "pods"))),
		capRule("RBACVIZ-R011", "Workload modification", SeverityHigh, 74, "An identity can update workload controllers", "Workload mutation may change images, commands, volumes, or ServiceAccounts.", "Restrict controller update/patch and separate deployment automation identities.", all(modify, func(value permission.Capability) bool {
			return groupMatches(value, "apps", "batch") && resourceMatches(value, "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs")
		})),
		capRule("RBACVIZ-R012", "Pod exec access", SeverityHigh, 75, "An identity can execute commands in Pods", "Interactive command execution can expose application data and mounted credentials.", "Restrict pods/exec to break-glass roles and audit its use.", all(verbIs("create", "get"), subresourceIs("", "pods", "exec"))),
		capRule("RBACVIZ-R013", "Pod attach access", SeverityHigh, 70, "An identity can attach to Pod processes", "Process attachment may expose application sessions and mounted credentials.", "Restrict pods/attach to tightly controlled operational roles.", all(verbIs("create", "get"), subresourceIs("", "pods", "attach"))),
		capRule("RBACVIZ-R014", "Pod port-forward access", SeverityMedium, 62, "An identity can port-forward to Pods", "Port forwarding may bypass ordinary network exposure controls.", "Restrict pods/portforward and monitor access to sensitive workloads.", all(verbIs("create", "get"), subresourceIs("", "pods", "portforward"))),
		capRule("RBACVIZ-R015", "Node proxy access", SeverityCritical, 91, "An identity can access the Node proxy subresource", "Node proxy can expose kubelet-backed operations and node-level workload access.", "Remove nodes/proxy access except from narrowly controlled platform components.", all(verbIs("get", "create"), subresourceIs("", "nodes", "proxy"))),
		capRule("RBACVIZ-R016", "Service proxy access", SeverityMedium, 58, "An identity can proxy to Services", "Service proxy may bypass expected ingress and network access paths.", "Restrict services/proxy and prefer explicitly governed service exposure.", all(verbIs("get", "create"), subresourceIs("", "services", "proxy"))),
		capRule("RBACVIZ-R017", "User impersonation", SeverityCritical, 94, "An identity can impersonate Kubernetes users", "Impersonation can assume the authorization of another user.", "Restrict impersonate to dedicated, audited components and named targets.", all(verbIs("impersonate"), resourceIs("", "users"))),
		capRule("RBACVIZ-R018", "Group impersonation", SeverityCritical, 96, "An identity can impersonate Kubernetes groups", "Group impersonation may confer broad or administrative authorization.", "Restrict impersonate on groups and require explicit resourceNames.", all(verbIs("impersonate"), resourceIs("", "groups"))),
		capRule("RBACVIZ-R019", "ServiceAccount impersonation", SeverityCritical, 91, "An identity can impersonate ServiceAccounts", "ServiceAccount impersonation can assume workload identity permissions.", "Restrict impersonate on serviceaccounts and require exact resourceNames.", all(verbIs("impersonate"), resourceIs("", "serviceaccounts"))),
		capRule("RBACVIZ-R020", "Role modification", SeverityHigh, 80, "An identity can create or modify Roles", "Role mutation can expand permissions available to namespaced bindings.", "Separate role administration and require narrowly scoped RBAC rules.", all(modify, resourceIs("rbac.authorization.k8s.io", "roles"))),
		capRule("RBACVIZ-R021", "ClusterRole modification", SeverityCritical, 88, "An identity can create or modify ClusterRoles", "ClusterRole mutation can expand permissions across namespaces or cluster-scoped resources.", "Restrict ClusterRole mutation to audited cluster-security administrators.", all(modify, resourceIs("rbac.authorization.k8s.io", "clusterroles"))),
		capRule("RBACVIZ-R022", "RoleBinding creation", SeverityHigh, 78, "An identity can create RoleBindings", "New RoleBindings can grant roles to additional subjects within a namespace.", "Restrict binding creation and separately control bind permission on referenced roles.", all(verbIs("create"), resourceIs("rbac.authorization.k8s.io", "rolebindings"))),
		capRule("RBACVIZ-R023", "ClusterRoleBinding creation", SeverityCritical, 89, "An identity can create ClusterRoleBindings", "New ClusterRoleBindings can grant cluster-wide capabilities to arbitrary subjects when bind checks permit it.", "Restrict ClusterRoleBinding creation and bind permission to audited administrators.", all(verbIs("create"), resourceIs("rbac.authorization.k8s.io", "clusterrolebindings"))),
		capRule("RBACVIZ-R024", "RBAC bind permission", SeverityCritical, 92, "An identity has the RBAC bind verb", "Bind can authorize assignment of roles whose permissions the caller does not already hold.", "Remove bind or constrain it to exact role resourceNames.", all(verbIs("bind"), func(value permission.Capability) bool {
			return groupMatches(value, "rbac.authorization.k8s.io") && resourceMatches(value, "roles", "clusterroles")
		})),
		capRule("RBACVIZ-R025", "RBAC escalate permission", SeverityCritical, 93, "An identity has the RBAC escalate verb", "Escalate can authorize creating or updating roles beyond the caller's current permissions.", "Remove escalate or constrain it to a tightly controlled administrative workflow.", all(verbIs("escalate"), func(value permission.Capability) bool {
			return groupMatches(value, "rbac.authorization.k8s.io") && resourceMatches(value, "roles", "clusterroles")
		})),
		capRule("RBACVIZ-R026", "CSR approval", SeverityCritical, 87, "An identity can approve certificate signing requests", "CSR approval may issue client certificates or node identities depending on signer permissions.", "Restrict CSR approval and signer access to dedicated certificate controllers.", csrApproval),
		capRule("RBACVIZ-R027", "Admission webhook modification", SeverityCritical, 90, "An identity can modify admission webhook configurations", "Webhook mutation can intercept, alter, allow, or deny API requests cluster-wide.", "Restrict admissionregistration resources to audited platform administrators.", all(modify, func(value permission.Capability) bool {
			return groupMatches(value, "admissionregistration.k8s.io") && resourceMatches(value, "mutatingwebhookconfigurations", "validatingwebhookconfigurations")
		})),
		workloadRule{metadata: workloadMeta("RBACVIZ-R028", "Privileged container", SeverityCritical, 92, "A workload declares a privileged container", "Privileged containers can bypass normal container isolation and reach host resources.", "Remove privileged mode and grant only the exact required capabilities."), match: workloadMatch{field: "spec.containers[].securityContext.privileged", values: privilegedContainers}},
		workloadRule{metadata: workloadMeta("RBACVIZ-R029", "Host network namespace", SeverityHigh, 78, "A workload enables hostNetwork", "The workload shares the node network namespace and may reach host-bound services.", "Disable hostNetwork unless it is an explicit platform requirement."), match: boolWorkloadField("spec.hostNetwork", func(value snapshot.Workload) bool { return value.HostNetwork })},
		workloadRule{metadata: workloadMeta("RBACVIZ-R030", "Host PID namespace", SeverityHigh, 82, "A workload enables hostPID", "The workload can observe or interact with host processes when other controls allow it.", "Disable hostPID and isolate process diagnostics in a controlled workflow."), match: boolWorkloadField("spec.hostPID", func(value snapshot.Workload) bool { return value.HostPID })},
		workloadRule{metadata: workloadMeta("RBACVIZ-R031", "Host IPC namespace", SeverityHigh, 76, "A workload enables hostIPC", "The workload shares host inter-process communication resources.", "Disable hostIPC unless a documented platform requirement exists."), match: boolWorkloadField("spec.hostIPC", func(value snapshot.Workload) bool { return value.HostIPC })},
		workloadRule{metadata: workloadMeta("RBACVIZ-R032", "HostPath volume", SeverityHigh, 84, "A workload declares a hostPath volume", "Host filesystem mounts can expose node credentials, sockets, or writable host state.", "Replace hostPath with managed storage or strictly constrain allowed paths and read-only mounts."), match: workloadMatch{field: "spec.volumes[].hostPath", values: hostPathVolumes}},
	}
	return rules
}

func capRule(id, title string, severity Severity, score int, description, impact, recommendation string, predicate capabilityPredicate) Rule {
	return capabilityRule{metadata: meta(id, title, severity, score, description, impact, recommendation, rbacReference), predicate: predicate}
}

func meta(id, title string, severity Severity, score int, description, impact, recommendation, reference string) RuleMetadata {
	return RuleMetadata{ID: id, Title: title, Severity: severity, RiskScore: score, Description: description, SecurityImpact: impact, Recommendations: []string{recommendation}, References: []string{reference}}
}

func workloadMeta(id, title string, severity Severity, score int, description, impact, recommendation string) RuleMetadata {
	return meta(id, title, severity, score, description, impact, recommendation, podSecurityStandards)
}

func groupMatches(value permission.Capability, groups ...string) bool {
	if value.APIGroup == "*" {
		return true
	}
	for _, group := range groups {
		if value.APIGroup == group {
			return true
		}
	}
	return false
}

func resourceMatches(value permission.Capability, resources ...string) bool {
	if value.Resource == "*" {
		return true
	}
	for _, resource := range resources {
		if value.Resource == resource {
			return true
		}
	}
	return false
}

func csrApproval(value permission.Capability) bool {
	if !groupMatches(value, "certificates.k8s.io") {
		return false
	}
	if strings.EqualFold(value.Verb, "approve") || value.Verb == "*" {
		return resourceMatches(value, "signers", "certificatesigningrequests")
	}
	return verbIs("update", "patch")(value) && subresourceIs("certificates.k8s.io", "certificatesigningrequests", "approval")(value)
}
