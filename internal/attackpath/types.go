// Package attackpath turns observed Kubernetes RBAC primitives into bounded,
// explainable privilege-escalation paths. It never reads Secret values and
// treats uninterpreted admission policy as uncertainty rather than proof.
package attackpath

import (
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the machine-readable attack-path contract.
	ResultSchemaVersion = "1.0"
	// TemplateSetVersion identifies the exact built-in technique catalog.
	TemplateSetVersion = "1.0.0"
)

// Confidence is an observation-bounded path state, not a probability.
type Confidence string

const (
	// ConfidenceConfirmed means all modeled conditions are directly observed.
	ConfidenceConfirmed Confidence = "CONFIRMED"
	// ConfidenceLikely means the RBAC chain is observed but runtime state is incomplete.
	ConfidenceLikely Confidence = "LIKELY"
	// ConfidenceConditional means an explicit additional condition is required.
	ConfidenceConditional Confidence = "CONDITIONAL"
	// ConfidenceBlocked means an evaluated control rejects a required step.
	ConfidenceBlocked Confidence = "BLOCKED"
	// ConfidenceUnknown means missing data or uninterpreted policy is material.
	ConfidenceUnknown Confidence = "UNKNOWN"
)

// PrivilegeTargetType is a stable class of security impact.
type PrivilegeTargetType string

const (
	// TargetClusterAdmin is unrestricted cluster administration.
	TargetClusterAdmin PrivilegeTargetType = "CLUSTER_ADMIN"
	// TargetSystemMasters is Kubernetes' privileged system group.
	TargetSystemMasters PrivilegeTargetType = "SYSTEM_MASTERS"
	// TargetRBACControl is authority to change authorization grants.
	TargetRBACControl PrivilegeTargetType = "RBAC_CONTROL"
	// TargetSecretAccess is access to potentially sensitive Secret objects.
	TargetSecretAccess PrivilegeTargetType = "SECRET_ACCESS"
	// TargetServiceAccountTakeover is the ability to act as a ServiceAccount.
	TargetServiceAccountTakeover PrivilegeTargetType = "SERVICE_ACCOUNT_TAKEOVER"
	// TargetWorkloadControl is authority over running workload definitions.
	TargetWorkloadControl PrivilegeTargetType = "WORKLOAD_CONTROL"
	// TargetAdmissionControl is authority over admission enforcement.
	TargetAdmissionControl PrivilegeTargetType = "ADMISSION_CONTROL"
	// TargetNodeControl is authority over Kubernetes nodes or kubelets.
	TargetNodeControl PrivilegeTargetType = "NODE_CONTROL"
	// TargetHostEscape is access from a Pod to its node host.
	TargetHostEscape PrivilegeTargetType = "HOST_ESCAPE"
	// TargetCloudIdentity is access to an external cloud workload identity.
	TargetCloudIdentity PrivilegeTargetType = "CLOUD_IDENTITY"
	// TargetCrossNamespaceControl is authority spanning namespace boundaries.
	TargetCrossNamespaceControl PrivilegeTargetType = "CROSS_NAMESPACE_CONTROL"
	// TargetPersistence is durable credential or authorization persistence.
	TargetPersistence PrivilegeTargetType = "PERSISTENCE"
)

// PrerequisiteState describes whether a material condition was observed.
type PrerequisiteState string

const (
	// PrerequisiteSatisfied means snapshot evidence supports the condition.
	PrerequisiteSatisfied PrerequisiteState = "SATISFIED"
	// PrerequisiteRequired means the operator must still provide the condition.
	PrerequisiteRequired PrerequisiteState = "REQUIRED"
	// PrerequisiteUnknown means collection cannot establish the condition.
	PrerequisiteUnknown PrerequisiteState = "UNKNOWN"
)

// Prerequisite is one explicit condition for exercising a technique.
type Prerequisite struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	State       PrerequisiteState `json:"state"`
	Evidence    string            `json:"evidence,omitempty"`
}

// MitigationState distinguishes observed blocking from potential controls.
type MitigationState string

const (
	// MitigationObserved is known metadata without a blocking conclusion.
	MitigationObserved MitigationState = "OBSERVED"
	// MitigationPotential is an uninterpreted control that may constrain a step.
	MitigationPotential MitigationState = "POTENTIAL"
	// MitigationBlocking is a semantically evaluated rejecting control.
	MitigationBlocking MitigationState = "BLOCKING"
)

// MitigationObservation records only what the snapshot can support.
type MitigationObservation struct {
	ID             string             `json:"id"`
	ControlType    string             `json:"controlType"`
	Ref            snapshot.ObjectRef `json:"ref"`
	State          MitigationState    `json:"state"`
	SemanticsKnown bool               `json:"semanticsKnown"`
	Reason         string             `json:"reason"`
}

// PermissionEvidence is the normalized action that enables a step.
type PermissionEvidence struct {
	Verb          string           `json:"verb"`
	APIGroup      string           `json:"apiGroup,omitempty"`
	Resource      string           `json:"resource,omitempty"`
	Subresource   string           `json:"subresource,omitempty"`
	ResourceNames []string         `json:"resourceNames"`
	Scope         permission.Scope `json:"scope"`
	Namespace     string           `json:"namespace,omitempty"`
}

// StepEvidence preserves the exact RBAC provenance and optional object field.
type StepEvidence struct {
	Permission *PermissionEvidence       `json:"permission,omitempty"`
	Grant      *permission.GrantEvidence `json:"grant,omitempty"`
	Ref        *snapshot.ObjectRef       `json:"ref,omitempty"`
	Field      string                    `json:"field,omitempty"`
	Value      string                    `json:"value,omitempty"`
}

// NodeRef is a portable endpoint used in a path explanation.
type NodeRef struct {
	Type      string `json:"type"`
	Key       string `json:"key"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// CostBreakdown exposes every additive path-ranking factor.
type CostBreakdown struct {
	BaseTechnique         int `json:"baseTechnique"`
	PrerequisitePenalty   int `json:"prerequisitePenalty"`
	UncertaintyPenalty    int `json:"uncertaintyPenalty"`
	MitigationPenalty     int `json:"mitigationPenalty"`
	OperationalComplexity int `json:"operationalComplexity"`
	Total                 int `json:"total"`
}

// AttackStep is one evidence-backed transition in an attack path.
type AttackStep struct {
	ID                    string                  `json:"id"`
	From                  NodeRef                 `json:"from"`
	To                    NodeRef                 `json:"to"`
	Relation              string                  `json:"relation"`
	TechniqueID           string                  `json:"techniqueId"`
	Description           string                  `json:"description"`
	Evidence              []StepEvidence          `json:"evidence"`
	Prerequisites         []Prerequisite          `json:"prerequisites"`
	MitigatingControls    []MitigationObservation `json:"mitigatingControls"`
	Confidence            Confidence              `json:"confidence"`
	ConfidenceReasons     []string                `json:"confidenceReasons"`
	Cost                  CostBreakdown           `json:"cost"`
	RemediationCandidates []string                `json:"remediationCandidates"`
}

// PrivilegeTarget describes the impact reached by a path.
type PrivilegeTarget struct {
	Type          PrivilegeTargetType `json:"type"`
	Key           string              `json:"key"`
	Namespace     string              `json:"namespace,omitempty"`
	Description   string              `json:"description"`
	PrivilegeGain int                 `json:"privilegeGain"`
	BlastRadius   int                 `json:"blastRadius"`
}

// Path is one ranked, loopless technique chain.
type Path struct {
	ID                string              `json:"id"`
	TemplateID        string              `json:"templateId"`
	Title             string              `json:"title"`
	Source            permission.Identity `json:"source"`
	Target            PrivilegeTarget     `json:"target"`
	Steps             []AttackStep        `json:"steps"`
	Confidence        Confidence          `json:"confidence"`
	ConfidenceReasons []string            `json:"confidenceReasons"`
	Cost              int                 `json:"cost"`
	Blocked           bool                `json:"blocked"`
}

// Warning keeps collection and resolution gaps visible in the result.
type Warning struct {
	Code    string              `json:"code"`
	Message string              `json:"message"`
	Ref     *snapshot.ObjectRef `json:"ref,omitempty"`
}

// Query bounds and filters one attack-path analysis.
type Query struct {
	From        *permission.Identity
	To          *PrivilegeTargetType
	Namespace   string
	Top         int
	MaxExpanded int
}

// Result is the deterministic output shared by CLI and future TUI.
type Result struct {
	SchemaVersion      string    `json:"schemaVersion"`
	TemplateSetVersion string    `json:"templateSetVersion"`
	Complete           bool      `json:"complete"`
	Paths              []Path    `json:"paths"`
	Expanded           int       `json:"expanded"`
	Truncated          bool      `json:"truncated"`
	Warnings           []Warning `json:"warnings"`
}
