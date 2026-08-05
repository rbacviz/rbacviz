// Package graph builds and queries the typed, directed multigraph used by
// rbacviz analysis. It contains no Kubernetes client or CLI concerns.
package graph

import (
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// SchemaVersion is the graph query wire-format version.
const SchemaVersion = "1.0"

// NodeType is a closed set of graph vertex categories.
type NodeType string

const (
	// NodeIdentity through NodePrivilegeTarget enumerate supported vertex types.
	NodeIdentity NodeType = "IDENTITY"
	// NodeServiceAccount is a namespaced workload identity.
	NodeServiceAccount NodeType = "SERVICE_ACCOUNT"
	// NodeBinding is a RoleBinding or ClusterRoleBinding.
	NodeBinding NodeType = "BINDING"
	// NodeRole is a namespaced Role.
	NodeRole NodeType = "ROLE"
	// NodeClusterRole is a ClusterRole.
	NodeClusterRole NodeType = "CLUSTER_ROLE"
	// NodeCapability is one normalized action selector.
	NodeCapability NodeType = "CAPABILITY"
	// NodeResourceSelector is a lazily expanded target.
	NodeResourceSelector NodeType = "RESOURCE_SELECTOR"
	// NodeWorkload is a workload controller.
	NodeWorkload NodeType = "WORKLOAD"
	// NodePod is a Pod.
	NodePod NodeType = "POD"
	// NodeSecret is Secret metadata without payload data.
	NodeSecret NodeType = "SECRET"
	// NodeNode is a Kubernetes Node asset.
	NodeNode NodeType = "NODE"
	// NodePersistentVolume is a cluster-scoped volume.
	NodePersistentVolume NodeType = "PERSISTENT_VOLUME"
	// NodeNamespace is a Kubernetes Namespace.
	NodeNamespace NodeType = "NAMESPACE"
	// NodeAsset is another security-relevant asset.
	NodeAsset NodeType = "ASSET"
	// NodeSecurityControl is an observed control.
	NodeSecurityControl NodeType = "SECURITY_CONTROL"
	// NodeAttackTechnique is reserved for security templates.
	NodeAttackTechnique NodeType = "ATTACK_TECHNIQUE"
	// NodePrivilegeTarget is reserved for typed privilege targets.
	NodePrivilegeTarget NodeType = "PRIVILEGE_TARGET"
)

// Relation is the semantic meaning of a directed edge.
type Relation string

const (
	// RelationBoundBy through RelationReaches enumerate structural transitions.
	RelationBoundBy Relation = "BOUND_BY"
	// RelationGrants connects a binding to its role reference.
	RelationGrants Relation = "GRANTS"
	// RelationAllows connects a role rule to a capability.
	RelationAllows Relation = "ALLOWS"
	// RelationRunsAs connects a workload to its ServiceAccount.
	RelationRunsAs Relation = "RUNS_AS"
	// RelationOwns represents object containment.
	RelationOwns Relation = "OWNS"
	// RelationMounts connects a workload to a volume target.
	RelationMounts Relation = "MOUNTS"
	// RelationReferences is an explicit object reference.
	RelationReferences Relation = "REFERENCES"
	// RelationReaches connects a capability to its lazy selector.
	RelationReaches Relation = "REACHES"
)

// Confidence is deliberately categorical. Security analysis extends these
// values in later milestones without converting them into fake probabilities.
type Confidence string

const (
	// ConfidenceConfirmed through ConfidenceUnknown enumerate evidence states.
	ConfidenceConfirmed Confidence = "CONFIRMED"
	// ConfidenceLikely marks incomplete runtime observation.
	ConfidenceLikely Confidence = "LIKELY"
	// ConfidenceConditional marks an explicit prerequisite.
	ConfidenceConditional Confidence = "CONDITIONAL"
	// ConfidenceBlocked marks an observed blocking control.
	ConfidenceBlocked Confidence = "BLOCKED"
	// ConfidenceUnknown marks materially missing information.
	ConfidenceUnknown Confidence = "UNKNOWN"
)

// Node is a portable graph vertex. Key is a human-usable, stable selector;
// ID is a compact hashed identifier suitable for persisted references.
type Node struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Key        string                 `json:"key"`
	Name       string                 `json:"name,omitempty"`
	Namespace  string                 `json:"namespace,omitempty"`
	Kind       string                 `json:"kind,omitempty"`
	Ref        *snapshot.ObjectRef    `json:"ref,omitempty"`
	Capability *permission.Capability `json:"capability,omitempty"`
}

// Evidence identifies the exact object or normalized rule behind an edge.
type Evidence struct {
	Kind   string                    `json:"kind"`
	Ref    *snapshot.ObjectRef       `json:"ref,omitempty"`
	Field  string                    `json:"field,omitempty"`
	Detail string                    `json:"detail,omitempty"`
	Grant  *permission.GrantEvidence `json:"grant,omitempty"`
}

// Edge is one evidence-backed transition in the directed multigraph.
type Edge struct {
	ID            string           `json:"id"`
	From          string           `json:"from"`
	To            string           `json:"to"`
	Relation      Relation         `json:"relation"`
	Evidence      []Evidence       `json:"evidence"`
	Scope         permission.Scope `json:"scope,omitempty"`
	Prerequisites []string         `json:"prerequisites"`
	Confidence    Confidence       `json:"confidence"`
	Cost          uint32           `json:"cost"`
	RuleID        string           `json:"ruleId,omitempty"`
}

// Warning records a graph construction ambiguity without hiding it.
type Warning struct {
	Code    string              `json:"code"`
	Message string              `json:"message"`
	Ref     *snapshot.ObjectRef `json:"ref,omitempty"`
}

// Stats is a stable summary suitable for CLI and TUI overview screens.
type Stats struct {
	SchemaVersion string          `json:"schemaVersion"`
	Nodes         int             `json:"nodes"`
	Edges         int             `json:"edges"`
	NodesByType   []TypeCount     `json:"nodesByType"`
	EdgesByType   []RelationCount `json:"edgesByRelation"`
	Warnings      int             `json:"warnings"`
}

// TypeCount is one node-type cardinality.
type TypeCount struct {
	Type  NodeType `json:"type"`
	Count int      `json:"count"`
}

// RelationCount is one edge-relation cardinality.
type RelationCount struct {
	Relation Relation `json:"relation"`
	Count    int      `json:"count"`
}

// Selector filters nodes without expanding resource selectors into every
// discovered Kubernetes object.
type Selector struct {
	Types     []NodeType
	Namespace string
	Kind      string
	Name      string
	KeyPrefix string
}

// Direction controls traversal across directed indexes.
type Direction string

const (
	// DirectionOutgoing through DirectionBoth enumerate traversal directions.
	DirectionOutgoing Direction = "outgoing"
	// DirectionIncoming follows reverse edge direction.
	DirectionIncoming Direction = "incoming"
	// DirectionBoth follows both edge indexes.
	DirectionBoth Direction = "both"
)

// TraversalLimits prevent accidental unbounded graph exploration.
type TraversalLimits struct {
	MaxDepth    int
	MaxExpanded int
}

// TraversalResult is a deterministic reachable-node query.
type TraversalResult struct {
	SchemaVersion string `json:"schemaVersion"`
	Start         string `json:"start"`
	Nodes         []Node `json:"nodes"`
	Expanded      int    `json:"expanded"`
	Truncated     bool   `json:"truncated"`
}

// PathLimits bound loopless weighted path search.
type PathLimits struct {
	K           int
	MaxDepth    int
	MaxExpanded int
}

// Path is one loopless sequence with its total non-negative edge cost.
type Path struct {
	ID    string `json:"id"`
	Cost  uint64 `json:"cost"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// PathResult contains bounded top-K paths in total deterministic rank order.
type PathResult struct {
	SchemaVersion string `json:"schemaVersion"`
	From          Node   `json:"from"`
	To            Node   `json:"to"`
	Paths         []Path `json:"paths"`
	Expanded      int    `json:"expanded"`
	Truncated     bool   `json:"truncated"`
}
