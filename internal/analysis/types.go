// Package analysis evaluates independently testable security rules over one
// canonical snapshot and its effective RBAC permissions.
package analysis

import (
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the machine-readable findings contract.
	ResultSchemaVersion = "1.0"
	// RulesetVersion identifies the exact built-in rule set.
	RulesetVersion = "1.0.0"
)

// Severity is an impact-oriented finding classification. Risk aggregation is
// deliberately deferred to the risk-engine milestone.
type Severity string

const (
	// SeverityCritical through SeverityInfo enumerate supported classifications.
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh marks a high-impact dangerous configuration.
	SeverityHigh Severity = "HIGH"
	// SeverityMedium marks a material but constrained configuration.
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow marks a lower-impact hardening opportunity.
	SeverityLow Severity = "LOW"
	// SeverityInfo marks a non-risk informational observation.
	SeverityInfo Severity = "INFO"
)

// Confidence describes how directly a finding is supported by observations.
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

// RuleMetadata is stable documentation and default classification for a rule.
type RuleMetadata struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        Severity `json:"severity"`
	RiskScore       int      `json:"riskScore"`
	Description     string   `json:"description"`
	SecurityImpact  string   `json:"securityImpact"`
	Recommendations []string `json:"recommendations"`
	References      []string `json:"references"`
}

// PermissionEvidence records the normalized selector that triggered a rule.
type PermissionEvidence struct {
	Verb           string           `json:"verb"`
	APIGroup       string           `json:"apiGroup,omitempty"`
	Resource       string           `json:"resource,omitempty"`
	Subresource    string           `json:"subresource,omitempty"`
	ResourceNames  []string         `json:"resourceNames"`
	NonResourceURL string           `json:"nonResourceURL,omitempty"`
	Scope          permission.Scope `json:"scope"`
	Namespace      string           `json:"namespace,omitempty"`
}

// Evidence points to an exact object field or independent RBAC grant.
type Evidence struct {
	Kind       string                    `json:"kind"`
	Ref        *snapshot.ObjectRef       `json:"ref,omitempty"`
	Field      string                    `json:"field,omitempty"`
	Value      string                    `json:"value,omitempty"`
	Permission *PermissionEvidence       `json:"permission,omitempty"`
	Grant      *permission.GrantEvidence `json:"grant,omitempty"`
}

// Finding is one evidence-backed observation produced by exactly one rule.
type Finding struct {
	ID                 string                `json:"id"`
	RuleID             string                `json:"ruleId"`
	Title              string                `json:"title"`
	Severity           Severity              `json:"severity"`
	RiskScore          int                   `json:"riskScore"`
	Confidence         Confidence            `json:"confidence"`
	Description        string                `json:"description"`
	SecurityImpact     string                `json:"securityImpact"`
	AffectedObjects    []snapshot.ObjectRef  `json:"affectedObjects"`
	AffectedIdentities []permission.Identity `json:"affectedIdentities"`
	Evidence           []Evidence            `json:"evidence"`
	Preconditions      []string              `json:"preconditions"`
	MitigatingControls []string              `json:"mitigatingControls"`
	AttackPaths        []string              `json:"attackPaths"`
	Recommendations    []string              `json:"recommendations"`
	References         []string              `json:"references"`
	fingerprint        string
}

// Warning preserves incomplete collection or permission-resolution context.
type Warning struct {
	Code    string              `json:"code"`
	Message string              `json:"message"`
	Ref     *snapshot.ObjectRef `json:"ref,omitempty"`
}

// Result is the deterministic findings output shared by CLI and future TUI.
type Result struct {
	SchemaVersion  string         `json:"schemaVersion"`
	RulesetVersion string         `json:"rulesetVersion"`
	Complete       bool           `json:"complete"`
	Rules          []RuleMetadata `json:"rules"`
	Findings       []Finding      `json:"findings"`
	Warnings       []Warning      `json:"warnings"`
}
