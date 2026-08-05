package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// Build creates the canonical graph used by traversal and later security
// analysis. Resource permissions end at lazy RESOURCE_SELECTOR nodes rather
// than being expanded across every discovered object.
func Build(input snapshot.Snapshot) (*Graph, error) {
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return nil, fmt.Errorf("canonicalize graph input: %w", err)
	}
	resolver, err := permission.New(canonical)
	if err != nil {
		return nil, fmt.Errorf("initialize permission graph: %w", err)
	}
	builder := &graphBuilder{nodes: make(map[string]Node), edges: make(map[string]Edge), objectNodes: make(map[string]string)}

	for _, identity := range canonical.Identities {
		builder.addIdentity(identity)
	}
	for _, role := range canonical.Roles {
		builder.addObjectNode(role.Ref, roleNodeType(role.Ref.Kind))
	}
	for _, binding := range canonical.Bindings {
		bindingID := builder.addObjectNode(binding.Ref, NodeBinding)
		roleID := builder.addObjectNode(binding.RoleRef, roleNodeType(binding.RoleRef.Kind))
		confidence := ConfidenceConfirmed
		if !hasRole(canonical.Roles, binding.RoleRef) {
			confidence = ConfidenceUnknown
			ref := binding.RoleRef
			builder.warnings = append(builder.warnings, Warning{Code: "MissingRoleRef", Message: fmt.Sprintf("%s %s references missing %s %s", binding.Ref.Kind, qualifiedRef(binding.Ref), binding.RoleRef.Kind, qualifiedRef(binding.RoleRef)), Ref: &ref})
		}
		builder.addEdge(bindingID, roleID, RelationGrants, "", confidence, 1, "", []Evidence{objectEvidence("roleRef", binding.Ref, "roleRef", qualifiedRef(binding.RoleRef))})
		for _, subject := range binding.Subjects {
			identityID := builder.addSubject(subject)
			builder.addEdge(identityID, bindingID, RelationBoundBy, "", ConfidenceConfirmed, 1, "", []Evidence{objectEvidence("bindingSubject", binding.Ref, "subjects", subjectDetail(subject))})
		}
	}

	for _, account := range canonical.ServiceAccounts {
		identityID := builder.addSubject(snapshot.Subject{Kind: snapshot.IdentityServiceAccount, Namespace: account.Ref.Namespace, Name: account.Ref.Name})
		builder.objectNodes[typedObjectKey(NodeServiceAccount, account.Ref)] = identityID
		builder.addNamespaceOwnership(account.Ref.Namespace, identityID, account.Ref)
	}
	for _, workload := range canonical.Workloads {
		builder.addWorkload(workload)
	}
	for _, asset := range canonical.Assets {
		builder.addAsset(asset)
	}
	for _, control := range canonical.SecurityControls {
		id := builder.addObjectNode(control.Ref, NodeSecurityControl)
		builder.addNamespaceOwnership(control.Ref.Namespace, id, control.Ref)
	}

	for _, identity := range canonical.Identities {
		query := permission.Identity{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name}
		builder.addIdentity(identity)
		result := resolver.Permissions(query, nil)
		for _, capability := range result.Capabilities {
			grants := append([]permission.GrantEvidence(nil), capability.Grants...)
			capability.Grants = nil
			capabilityID := builder.addCapability(capability)
			selectorID := builder.addSelector(capability)
			confidence := ConfidenceConfirmed
			if !canonical.Metadata.Complete || capability.Scope == permission.ScopeUnknown {
				confidence = ConfidenceUnknown
			}
			builder.addEdge(capabilityID, selectorID, RelationReaches, capability.Scope, confidence, 1, "", []Evidence{{Kind: "normalizedCapability", Detail: capabilityNodeKey(capability)}})
			for _, grant := range grants {
				roleID := builder.addObjectNode(grant.RoleRef, roleNodeType(grant.RoleRef.Kind))
				builder.addEdge(roleID, capabilityID, RelationAllows, capability.Scope, confidence, 1, grant.PolicyRuleID, []Evidence{grantEvidence("policyRule", grant)})
			}
		}
	}

	nodes := make([]Node, 0, len(builder.nodes))
	for _, node := range builder.nodes {
		nodes = append(nodes, node)
	}
	edges := make([]Edge, 0, len(builder.edges))
	for _, edge := range builder.edges {
		edges = append(edges, edge)
	}
	return New(nodes, edges, canonicalWarnings(builder.warnings))
}

type graphBuilder struct {
	nodes       map[string]Node
	edges       map[string]Edge
	objectNodes map[string]string
	warnings    []Warning
}

func (builder *graphBuilder) addIdentity(identity snapshot.Identity) string {
	typeValue := NodeIdentity
	if identity.Kind == snapshot.IdentityServiceAccount {
		typeValue = NodeServiceAccount
	}
	key := identityNodeKey(identity.Kind, identity.Namespace, identity.Name)
	id := stableID("node", string(typeValue), key)
	builder.nodes[id] = Node{ID: id, Type: typeValue, Key: key, Name: identity.Name, Namespace: identity.Namespace, Kind: string(identity.Kind)}
	return id
}

func (builder *graphBuilder) addSubject(subject snapshot.Subject) string {
	return builder.addIdentity(snapshot.Identity{Kind: subject.Kind, Namespace: subject.Namespace, Name: subject.Name})
}

func (builder *graphBuilder) addObjectNode(ref snapshot.ObjectRef, nodeType NodeType) string {
	object := typedObjectKey(nodeType, ref)
	if id, found := builder.objectNodes[object]; found {
		return id
	}
	if ref.Kind == "ServiceAccount" && nodeType == NodeServiceAccount {
		id := builder.addSubject(snapshot.Subject{Kind: snapshot.IdentityServiceAccount, Namespace: ref.Namespace, Name: ref.Name})
		builder.objectNodes[object] = id
		builder.addNamespaceOwnership(ref.Namespace, id, ref)
		return id
	}
	key := objectNodeKey(nodeType, ref)
	id := stableID("node", string(nodeType), key)
	copyRef := ref
	builder.nodes[id] = Node{ID: id, Type: nodeType, Key: key, Name: ref.Name, Namespace: ref.Namespace, Kind: ref.Kind, Ref: &copyRef}
	builder.objectNodes[object] = id
	if ref.Kind != "Namespace" {
		builder.addNamespaceOwnership(ref.Namespace, id, ref)
	}
	return id
}

func (builder *graphBuilder) addNamespaceOwnership(namespace, childID string, childRef snapshot.ObjectRef) {
	if namespace == "" {
		return
	}
	ref := snapshot.ObjectRef{Kind: "Namespace", Name: namespace}
	namespaceID := builder.addObjectNode(ref, NodeNamespace)
	builder.addEdge(namespaceID, childID, RelationOwns, permission.ScopeNamespaced, ConfidenceConfirmed, 1, "", []Evidence{objectEvidence("objectNamespace", childRef, "metadata.namespace", namespace)})
}

func (builder *graphBuilder) addWorkload(workload snapshot.Workload) {
	nodeType := NodeWorkload
	if workload.Ref.Kind == "Pod" {
		nodeType = NodePod
	}
	workloadID := builder.addObjectNode(workload.Ref, nodeType)
	if workload.ServiceAccountName != "" {
		subject := snapshot.Subject{Kind: snapshot.IdentityServiceAccount, Namespace: workload.Ref.Namespace, Name: workload.ServiceAccountName}
		accountID := builder.addSubject(subject)
		builder.objectNodes[typedObjectKey(NodeServiceAccount, snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: workload.Ref.Namespace, Name: workload.ServiceAccountName})] = accountID
		builder.addEdge(workloadID, accountID, RelationRunsAs, permission.ScopeNamespaced, ConfidenceConfirmed, 1, "", []Evidence{objectEvidence("workloadIdentity", workload.Ref, "spec.serviceAccountName", workload.ServiceAccountName)})
	}
	for _, owner := range workload.Owners {
		ownerID := builder.addObjectNode(owner.Ref, workloadNodeType(owner.Ref.Kind))
		builder.addEdge(ownerID, workloadID, RelationOwns, permission.ScopeNamespaced, ConfidenceConfirmed, 1, "", []Evidence{objectEvidence("ownerReference", workload.Ref, "metadata.ownerReferences", qualifiedRef(owner.Ref))})
	}
	for _, volume := range workload.Volumes {
		if volume.Target == "" {
			continue
		}
		ref := snapshot.ObjectRef{Kind: volume.Kind, Namespace: volume.Namespace, Name: volume.Target}
		targetType := assetNodeType(ref.Kind)
		if volume.Kind == "ServiceAccountToken" {
			ref.Kind = "ServiceAccount"
			targetType = NodeServiceAccount
		}
		targetID := builder.addObjectNode(ref, targetType)
		builder.addEdge(workloadID, targetID, RelationMounts, permission.ScopeNamespaced, ConfidenceConfirmed, 1, "", []Evidence{objectEvidence("volume", workload.Ref, "spec.volumes["+volume.Name+"]", volume.Kind+":"+volume.Target)})
	}
}

func (builder *graphBuilder) addAsset(asset snapshot.Asset) {
	id := builder.addObjectNode(asset.Ref, assetNodeType(asset.Ref.Kind))
	builder.addNamespaceOwnership(asset.Ref.Namespace, id, asset.Ref)
}

func (builder *graphBuilder) addCapability(capability permission.Capability) string {
	key := capabilityNodeKey(capability)
	id := stableID("node", string(NodeCapability), key)
	copyValue := capability
	copyValue.Grants = []permission.GrantEvidence{}
	builder.nodes[id] = Node{ID: id, Type: NodeCapability, Key: key, Name: capability.Verb, Namespace: capability.Namespace, Kind: "Capability", Capability: &copyValue}
	return id
}

func (builder *graphBuilder) addSelector(capability permission.Capability) string {
	key := selectorNodeKey(capability)
	id := stableID("node", string(NodeResourceSelector), key)
	copyValue := capability
	copyValue.Verb = ""
	copyValue.Grants = []permission.GrantEvidence{}
	builder.nodes[id] = Node{ID: id, Type: NodeResourceSelector, Key: key, Name: selectorName(capability), Namespace: capability.Namespace, Kind: "ResourceSelector", Capability: &copyValue}
	return id
}

func (builder *graphBuilder) addEdge(from, to string, relation Relation, scope permission.Scope, confidence Confidence, cost uint32, ruleID string, evidence []Evidence) {
	parts := []string{from, to, string(relation), ruleID}
	for _, item := range evidence {
		parts = append(parts, item.Kind, item.Field, item.Detail)
		if item.Grant != nil {
			parts = append(parts, item.Grant.ID)
		}
	}
	id := stableID("edge", parts...)
	if _, exists := builder.edges[id]; exists {
		return
	}
	builder.edges[id] = Edge{ID: id, From: from, To: to, Relation: relation, Evidence: evidence, Scope: scope, Prerequisites: []string{}, Confidence: confidence, Cost: cost, RuleID: ruleID}
}

func grantEvidence(kind string, grant permission.GrantEvidence) Evidence {
	ref := grant.BindingRef
	detail := grant.ID
	if kind == "policyRule" {
		ref = grant.SourceRoleRef
		detail = grant.PolicyRuleID
	}
	if kind == "roleRef" {
		detail = qualifiedRef(grant.RoleRef)
	}
	copyGrant := grant
	return Evidence{Kind: kind, Ref: &ref, Detail: detail, Grant: &copyGrant}
}

func objectEvidence(kind string, ref snapshot.ObjectRef, field, detail string) Evidence {
	copyRef := ref
	return Evidence{Kind: kind, Ref: &copyRef, Field: field, Detail: detail}
}

func identityNodeKey(kind snapshot.IdentityKind, namespace, name string) string {
	switch kind {
	case snapshot.IdentityServiceAccount:
		return "identity:serviceaccount:" + namespace + ":" + name
	case snapshot.IdentityGroup:
		return "identity:group:" + name
	default:
		return "identity:user:" + name
	}
}

func objectNodeKey(nodeType NodeType, ref snapshot.ObjectRef) string {
	return strings.ToLower(string(nodeType)) + ":" + strings.ToLower(ref.Kind) + ":" + ref.Namespace + ":" + ref.Name
}

func objectKey(ref snapshot.ObjectRef) string {
	return strings.Join([]string{ref.APIGroup, ref.Kind, ref.Namespace, ref.Name}, "\x00")
}

func typedObjectKey(nodeType NodeType, ref snapshot.ObjectRef) string {
	return string(nodeType) + "\x00" + objectKey(ref)
}

func capabilityNodeKey(value permission.Capability) string {
	data, _ := json.Marshal(struct {
		Verb, Group, Resource, Subresource, URL string
		Names                                   []string
		Scope                                   permission.Scope
		Namespace                               string
	}{value.Verb, value.APIGroup, value.Resource, value.Subresource, value.NonResourceURL, value.ResourceNames, value.Scope, value.Namespace})
	return "capability:" + string(data)
}

func selectorNodeKey(value permission.Capability) string {
	copyValue := value
	copyValue.Verb = ""
	return strings.Replace(capabilityNodeKey(copyValue), "capability:", "selector:", 1)
}

func selectorName(value permission.Capability) string {
	if value.NonResourceURL != "" {
		return value.NonResourceURL
	}
	name := value.Resource
	if value.APIGroup != "" {
		name += "." + value.APIGroup
	}
	if value.Subresource != "" {
		name += "/" + value.Subresource
	}
	return name
}

func roleNodeType(kind string) NodeType {
	if kind == "ClusterRole" {
		return NodeClusterRole
	}
	return NodeRole
}
func workloadNodeType(kind string) NodeType {
	if kind == "Pod" {
		return NodePod
	}
	return NodeWorkload
}
func assetNodeType(kind string) NodeType {
	switch kind {
	case "Secret":
		return NodeSecret
	case "Node":
		return NodeNode
	case "PersistentVolume":
		return NodePersistentVolume
	case "Namespace":
		return NodeNamespace
	default:
		return NodeAsset
	}
}

func hasRole(roles []snapshot.Role, ref snapshot.ObjectRef) bool {
	for _, role := range roles {
		if objectKey(role.Ref) == objectKey(ref) {
			return true
		}
	}
	return false
}
func qualifiedRef(ref snapshot.ObjectRef) string {
	if ref.Namespace == "" {
		return ref.Name
	}
	return ref.Namespace + "/" + ref.Name
}
func subjectDetail(subject snapshot.Subject) string {
	return identityNodeKey(subject.Kind, subject.Namespace, subject.Name)
}

func canonicalWarnings(values []Warning) []Warning {
	sort.Slice(values, func(i, j int) bool {
		return values[i].Code+"\x00"+values[i].Message < values[j].Code+"\x00"+values[j].Message
	})
	result := make([]Warning, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1].Code != value.Code || result[len(result)-1].Message != value.Message {
			result = append(result, value)
		}
	}
	return result
}
