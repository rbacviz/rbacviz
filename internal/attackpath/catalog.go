package attackpath

import "strings"

// TemplateMetadata describes a stable built-in attack technique.
type TemplateMetadata struct {
	ID                    string
	Title                 string
	Target                PrivilegeTargetType
	Description           string
	BaseCost              int
	OperationalComplexity int
	PrivilegeGain         int
	BlastRadius           int
	Remediations          []string
}

var templates = []TemplateMetadata{
	{"RBACVIZ-AP001", "Direct cluster-admin grant", TargetClusterAdmin, "An observed binding directly grants cluster-admin.", 0, 0, 100, 100, []string{"Remove the cluster-admin binding or replace it with a least-privilege role."}},
	{"RBACVIZ-AP002", "system:masters membership", TargetSystemMasters, "An observed binding targets the system:masters group.", 0, 0, 100, 100, []string{"Remove explicit system:masters grants and use auditable RBAC roles."}},
	{"RBACVIZ-AP003", "ServiceAccount token minting", TargetServiceAccountTakeover, "Create a token for an addressable ServiceAccount and assume its identity.", 2, 1, 85, 60, []string{"Remove create on serviceaccounts/token or restrict resourceNames."}},
	{"RBACVIZ-AP004", "Workload identity takeover", TargetServiceAccountTakeover, "Create or mutate a workload that runs as a more privileged ServiceAccount.", 3, 2, 82, 60, []string{"Restrict workload creation and mutation; constrain allowed ServiceAccounts with admission policy."}},
	{"RBACVIZ-AP005", "Secret-to-identity inference", TargetSecretAccess, "Read Secret objects that may contain workload or external credentials.", 2, 1, 72, 45, []string{"Restrict Secret read access by namespace and resourceNames."}},
	{"RBACVIZ-AP006", "RBAC bind escalation", TargetRBACControl, "Use the bind verb to attach an existing role to a controlled subject.", 2, 2, 92, 85, []string{"Remove bind and narrowly scope role resourceNames."}},
	{"RBACVIZ-AP007", "RBAC rule escalation", TargetRBACControl, "Use the escalate verb to create or update a role beyond current permissions.", 2, 2, 92, 85, []string{"Remove escalate and separate RBAC administration duties."}},
	{"RBACVIZ-AP008", "Binding mutation", TargetRBACControl, "Create or modify RoleBindings or ClusterRoleBindings.", 3, 2, 88, 80, []string{"Restrict binding mutation and review redundant RBAC administration grants."}},
	{"RBACVIZ-AP009", "Identity impersonation", TargetServiceAccountTakeover, "Impersonate an authorized user, group, or ServiceAccount.", 2, 1, 90, 75, []string{"Remove impersonate or constrain exact resourceNames."}},
	{"RBACVIZ-AP010", "Node proxy takeover", TargetNodeControl, "Reach kubelet-backed node operations through nodes/proxy.", 2, 2, 94, 95, []string{"Remove nodes/proxy access and use narrowly scoped operational APIs."}},
	{"RBACVIZ-AP011", "CSR approval persistence", TargetPersistence, "Approve a crafted certificate signing request that may create durable credentials.", 3, 3, 86, 80, []string{"Separate CSR creation and approval; restrict signerNames and approval permissions."}},
	{"RBACVIZ-AP012", "Privileged workload host escape", TargetHostEscape, "Create a privileged or host-mounted workload that reaches the node host.", 4, 3, 98, 95, []string{"Enforce Pod Security Admission and remove unconstrained Pod creation."}},
}

func templateByID(id string) TemplateMetadata {
	for _, item := range templates {
		if item.ID == id {
			item.Remediations = append([]string(nil), item.Remediations...)
			return item
		}
	}
	return TemplateMetadata{}
}

// ParseTarget accepts stable names and user-friendly CLI aliases.
func ParseTarget(value string) (PrivilegeTargetType, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	for _, candidate := range allTargets() {
		if normalized == string(candidate) {
			return candidate, nil
		}
	}
	return "", targetParseError(value)
}

func allTargets() []PrivilegeTargetType {
	return []PrivilegeTargetType{TargetClusterAdmin, TargetSystemMasters, TargetRBACControl, TargetSecretAccess, TargetServiceAccountTakeover, TargetWorkloadControl, TargetAdmissionControl, TargetNodeControl, TargetHostEscape, TargetCloudIdentity, TargetCrossNamespaceControl, TargetPersistence}
}
