package attackpath

import (
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func (engine *Engine) candidatesForGrant(source permission.Identity, all []permission.Capability, capability permission.Capability, grant permission.GrantEvidence) []candidate {
	result := make([]candidate, 0, 3)
	if capabilityMatches(capability, []string{"create"}, []string{""}, []string{"serviceaccounts"}, []string{"token"}) {
		result = append(result, engine.serviceAccountCandidates("RBACVIZ-AP003", source, capability, grant, false)...)
	}
	if isWorkloadMutation(capability) {
		result = append(result, engine.workloadTakeoverCandidates(source, capability, grant)...)
	}
	if capabilityMatches(capability, []string{"get", "list", "watch"}, []string{""}, []string{"secrets"}, []string{""}) {
		result = append(result, engine.secretCandidate(source, capability, grant))
	}
	if capabilityMatches(capability, []string{"bind"}, []string{"rbac.authorization.k8s.io"}, []string{"roles", "clusterroles"}, []string{""}) {
		result = append(result, engine.rbacBindCandidate(source, all, capability, grant))
	}
	if capabilityMatches(capability, []string{"escalate"}, []string{"rbac.authorization.k8s.io"}, []string{"roles", "clusterroles"}, []string{""}) {
		result = append(result, engine.rbacEscalateCandidate(source, all, capability, grant))
	}
	if capabilityMatches(capability, []string{"create", "update", "patch"}, []string{"rbac.authorization.k8s.io"}, []string{"rolebindings", "clusterrolebindings"}, []string{""}) {
		result = append(result, engine.bindingMutationCandidate(source, capability, grant))
	}
	if capabilityMatches(capability, []string{"impersonate"}, nil, []string{"users", "groups", "serviceaccounts"}, []string{""}) {
		result = append(result, engine.impersonationCandidate(source, capability, grant))
	}
	if capabilityMatches(capability, []string{"get", "create", "update", "patch", "*"}, []string{""}, []string{"nodes"}, []string{"proxy"}) {
		result = append(result, engine.simpleCapabilityCandidate("RBACVIZ-AP010", source, capability, grant, ""))
	}
	if capabilityMatches(capability, []string{"update", "patch"}, []string{"certificates.k8s.io"}, []string{"certificatesigningrequests"}, []string{"approval"}) {
		result = append(result, engine.csrCandidate(source, all, capability, grant))
	}
	if capabilityMatches(capability, []string{"create"}, []string{""}, []string{"pods"}, []string{""}) {
		result = append(result, engine.hostEscapeCandidate(source, capability, grant))
	}
	return result
}

func (engine *Engine) serviceAccountCandidates(templateID string, source permission.Identity, capability permission.Capability, grant permission.GrantEvidence, workloadOnly bool) []candidate {
	metadata := templateByID(templateID)
	namespace := capabilityNamespace(capability, source)
	accounts := engine.addressableServiceAccounts(capability, namespace, workloadOnly)
	if len(accounts) == 0 {
		prerequisite := Prerequisite{ID: "target-serviceaccount", Description: "an addressable ServiceAccount with useful privileges exists", State: PrerequisiteUnknown}
		return []candidate{engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, namespace, "unknown"), []Prerequisite{prerequisite})}
	}
	result := make([]candidate, 0, len(accounts))
	for _, account := range accounts {
		prerequisite := Prerequisite{ID: "target-serviceaccount", Description: "target ServiceAccount exists and is addressable", State: PrerequisiteSatisfied, Evidence: account.Ref.Namespace + "/" + account.Ref.Name}
		value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, account.Ref.Namespace, account.Ref.Name), []Prerequisite{prerequisite})
		ref := account.Ref
		value.object = &ref
		value.objectField = "metadata.name"
		value.objectValue = account.Ref.Name
		result = append(result, value)
	}
	return result
}

func (engine *Engine) addressableServiceAccounts(capability permission.Capability, namespace string, workloadOnly bool) []snapshot.ServiceAccount {
	used := make(map[string]struct{})
	if workloadOnly {
		for _, workload := range engine.input.Workloads {
			if workload.ServiceAccountName != "" {
				used[workload.Ref.Namespace+"\x00"+workload.ServiceAccountName] = struct{}{}
			}
		}
	}
	result := make([]snapshot.ServiceAccount, 0)
	for _, account := range engine.input.ServiceAccounts {
		if namespace != "" && account.Ref.Namespace != namespace {
			continue
		}
		if !addressesName(capability, account.Ref.Name) {
			continue
		}
		if workloadOnly {
			if _, ok := used[account.Ref.Namespace+"\x00"+account.Ref.Name]; !ok {
				continue
			}
		}
		result = append(result, account)
	}
	return result
}

func (engine *Engine) workloadTakeoverCandidates(source permission.Identity, capability permission.Capability, grant permission.GrantEvidence) []candidate {
	values := engine.serviceAccountCandidates("RBACVIZ-AP004", source, capability, grant, capability.Verb != "create")
	for index := range values {
		values[index].controls = engine.controlsFor(values[index].metadata.ID, values[index].target.Namespace)
		values[index].baseConfidence = ConfidenceLikely
		values[index].prerequisites = append(values[index].prerequisites, Prerequisite{ID: "workload-admission", Description: "admission permits the selected ServiceAccount reference and workload mutation", State: PrerequisiteRequired})
	}
	return values
}

func (engine *Engine) secretCandidate(source permission.Identity, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP005")
	namespace := capabilityNamespace(capability, source)
	name := "*"
	if len(capability.ResourceNames) == 1 {
		name = capability.ResourceNames[0]
	}
	prerequisites := []Prerequisite{{ID: "credential-bearing-secret", Description: "an addressable Secret contains useful identity or external-system credentials", State: PrerequisiteRequired, Evidence: "Secret values are intentionally not collected"}}
	value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, namespace, name), prerequisites)
	value.baseConfidence = ConfidenceConditional
	value.reasons = append(value.reasons, "Secret metadata proves access scope but not credential contents")
	return value
}

func (engine *Engine) rbacBindCandidate(source permission.Identity, all []permission.Capability, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP006")
	state := PrerequisiteRequired
	evidence := ""
	if hasCapability(all, []string{"create", "update", "patch"}, []string{"rbac.authorization.k8s.io"}, []string{"rolebindings", "clusterrolebindings"}, []string{""}) {
		state = PrerequisiteSatisfied
		evidence = "binding mutation permission is observed"
	}
	prerequisites := []Prerequisite{{ID: "binding-mutation", Description: "the identity can create or modify a binding that references the target role", State: state, Evidence: evidence}, {ID: "target-role", Description: "an addressable role provides the desired privilege", State: PrerequisiteRequired}}
	value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, capabilityNamespace(capability, source), roleQualifier(capability)), prerequisites)
	value.controls = engine.controlsFor(metadata.ID, value.target.Namespace)
	return value
}

func (engine *Engine) rbacEscalateCandidate(source permission.Identity, all []permission.Capability, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP007")
	state := PrerequisiteRequired
	if hasCapability(all, []string{"create", "update", "patch"}, []string{"rbac.authorization.k8s.io"}, []string{"roles", "clusterroles"}, []string{""}) {
		state = PrerequisiteSatisfied
	}
	prerequisites := []Prerequisite{{ID: "role-mutation", Description: "the identity can create or modify the addressed Role or ClusterRole", State: state}}
	value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, capabilityNamespace(capability, source), roleQualifier(capability)), prerequisites)
	value.controls = engine.controlsFor(metadata.ID, value.target.Namespace)
	return value
}

func (engine *Engine) bindingMutationCandidate(source permission.Identity, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP008")
	prerequisites := []Prerequisite{{ID: "usable-role", Description: "a role can be referenced without the API server rejecting privilege escalation", State: PrerequisiteRequired}}
	value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, capabilityNamespace(capability, source), capability.Resource), prerequisites)
	value.controls = engine.controlsFor(metadata.ID, value.target.Namespace)
	return value
}

func (engine *Engine) impersonationCandidate(source permission.Identity, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP009")
	qualifier := capability.Resource
	if len(capability.ResourceNames) == 1 {
		qualifier += ":" + capability.ResourceNames[0]
	}
	prerequisites := []Prerequisite{{ID: "privileged-target-identity", Description: "an addressable impersonation target has useful privileges", State: PrerequisiteRequired}}
	return engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, capabilityNamespace(capability, source), qualifier), prerequisites)
}

func (engine *Engine) csrCandidate(source permission.Identity, all []permission.Capability, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP011")
	state := PrerequisiteRequired
	if hasCapability(all, []string{"create"}, []string{"certificates.k8s.io"}, []string{"certificatesigningrequests"}, []string{""}) {
		state = PrerequisiteSatisfied
	}
	prerequisites := []Prerequisite{{ID: "csr-creation", Description: "a crafted CSR can be created or supplied for approval", State: state}, {ID: "trusted-signer", Description: "the selected signer issues credentials accepted by a target authenticator", State: PrerequisiteRequired}}
	value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, "", "csr"), prerequisites)
	value.controls = engine.controlsFor(metadata.ID, "")
	return value
}

func (engine *Engine) hostEscapeCandidate(source permission.Identity, capability permission.Capability, grant permission.GrantEvidence) candidate {
	metadata := templateByID("RBACVIZ-AP012")
	namespace := capabilityNamespace(capability, source)
	nodeState := PrerequisiteUnknown
	for _, asset := range engine.input.Assets {
		if asset.Ref.Kind == "Node" {
			nodeState = PrerequisiteSatisfied
			break
		}
	}
	prerequisites := []Prerequisite{
		{ID: "host-access-pod", Description: "the modeled Pod requests privileged execution or host access", State: PrerequisiteSatisfied, Evidence: "template-controlled Pod specification"},
		{ID: "schedulable-node", Description: "a suitable node accepts and runs the Pod", State: nodeState},
	}
	value := engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, namespace, "node-host"), prerequisites)
	value.controls = engine.controlsFor(metadata.ID, namespace)
	return value
}

func (engine *Engine) simpleCapabilityCandidate(templateID string, source permission.Identity, capability permission.Capability, grant permission.GrantEvidence, qualifier string) candidate {
	metadata := templateByID(templateID)
	return engine.newCapabilityCandidate(metadata, source, capability, grant, newTarget(metadata, metadata.Target, capabilityNamespace(capability, source), qualifier), nil)
}

func (engine *Engine) newCapabilityCandidate(metadata TemplateMetadata, source permission.Identity, capability permission.Capability, grant permission.GrantEvidence, target PrivilegeTarget, prerequisites []Prerequisite) candidate {
	capCopy := capability
	capCopy.Grants = nil
	grantCopy := grant
	return candidate{metadata: metadata, source: source, target: target, capability: &capCopy, grant: &grantCopy, prerequisites: prerequisites, controls: []MitigationObservation{}, baseConfidence: ConfidenceLikely, scopeNamespace: capabilityNamespace(capability, source)}
}

func isWorkloadMutation(value permission.Capability) bool {
	if !fieldMatches(value.Verb, []string{"create", "update", "patch"}) || value.Subresource != "" {
		return false
	}
	if fieldMatches(value.APIGroup, []string{""}) && fieldMatches(value.Resource, []string{"pods"}) {
		return true
	}
	return fieldMatches(value.APIGroup, []string{"apps", "batch"}) && fieldMatches(value.Resource, []string{"deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"})
}

func roleQualifier(value permission.Capability) string {
	if len(value.ResourceNames) == 1 {
		return strings.TrimSuffix(value.Resource, "s") + ":" + value.ResourceNames[0]
	}
	return value.Resource
}
