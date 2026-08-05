// Package diff computes deterministic, security-semantic differences between
// two canonical snapshots. It compares derived authorization and attack
// analysis rather than treating serialized Kubernetes objects as the answer.
package diff

import (
	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the machine-readable semantic diff contract.
	ResultSchemaVersion = "1.0"
)

// Options bounds the derived analyses used by a diff.
type Options struct {
	MaxPaths    int
	MaxExpanded int
}

// Direction describes which side introduced a semantic value.
type Direction string

const (
	// Added means present only after the change.
	Added Direction = "ADDED"
	// Removed means present only before the change.
	Removed Direction = "REMOVED"
)

// ObjectSummary is a stable, content-addressed object description.
type ObjectSummary struct {
	Category string             `json:"category"`
	Ref      snapshot.ObjectRef `json:"ref"`
	Digest   string             `json:"digest"`
}

// ObjectModification records a same-key object whose relevant content changed.
type ObjectModification struct {
	Category     string             `json:"category"`
	Ref          snapshot.ObjectRef `json:"ref"`
	BeforeDigest string             `json:"beforeDigest"`
	AfterDigest  string             `json:"afterDigest"`
}

// ObjectDiff is the canonical structural snapshot delta.
type ObjectDiff struct {
	Added    []ObjectSummary      `json:"added"`
	Removed  []ObjectSummary      `json:"removed"`
	Modified []ObjectModification `json:"modified"`
}

// IdentityDiff compares directly observed subjects.
type IdentityDiff struct {
	Added   []permission.Identity `json:"added"`
	Removed []permission.Identity `json:"removed"`
}

// Capability is a permission selector without provenance.
type Capability struct {
	Verb           string           `json:"verb"`
	APIGroup       string           `json:"apiGroup,omitempty"`
	Resource       string           `json:"resource,omitempty"`
	Subresource    string           `json:"subresource,omitempty"`
	ResourceNames  []string         `json:"resourceNames"`
	NonResourceURL string           `json:"nonResourceURL,omitempty"`
	Scope          permission.Scope `json:"scope"`
	Namespace      string           `json:"namespace,omitempty"`
}

// GrantSummary keeps stable provenance without repeating the complete rule.
type GrantSummary struct {
	ID         string             `json:"id"`
	BindingRef snapshot.ObjectRef `json:"bindingRef"`
	RoleRef    snapshot.ObjectRef `json:"roleRef"`
}

// GrantChange captures provenance-only changes for an unchanged capability.
type GrantChange struct {
	Capability Capability     `json:"capability"`
	Added      []GrantSummary `json:"added"`
	Removed    []GrantSummary `json:"removed"`
}

// PermissionDiff is the effective authorization delta for one identity.
type PermissionDiff struct {
	Identity      permission.Identity `json:"identity"`
	Added         []Capability        `json:"added"`
	Removed       []Capability        `json:"removed"`
	ChangedGrants []GrantChange       `json:"changedGrants"`
}

// DangerousCapabilityChange gives security meaning to a permission delta.
type DangerousCapabilityChange struct {
	Direction  Direction           `json:"direction"`
	Category   string              `json:"category"`
	Identity   permission.Identity `json:"identity"`
	Capability Capability          `json:"capability"`
}

// FindingSummary is the stable part of a finding needed for comparison.
type FindingSummary struct {
	ID         string              `json:"id"`
	RuleID     string              `json:"ruleId"`
	Title      string              `json:"title"`
	Severity   analysis.Severity   `json:"severity"`
	RiskScore  int                 `json:"riskScore"`
	Confidence analysis.Confidence `json:"confidence"`
}

// FindingDiff compares evidence-backed observations.
type FindingDiff struct {
	Added   []FindingSummary `json:"added"`
	Removed []FindingSummary `json:"removed"`
}

// PathSummary is a portable attack-path comparison record.
type PathSummary struct {
	ID         string                     `json:"id"`
	TemplateID string                     `json:"templateId"`
	Title      string                     `json:"title"`
	Source     permission.Identity        `json:"source"`
	Target     attackpath.PrivilegeTarget `json:"target"`
	Confidence attackpath.Confidence      `json:"confidence"`
	Blocked    bool                       `json:"blocked"`
	Cost       int                        `json:"cost"`
}

// PathStateChange records changed confidence, blocking, or cost for the same
// semantic source/template/target path unit.
type PathStateChange struct {
	Key    string      `json:"key"`
	Before PathSummary `json:"before"`
	After  PathSummary `json:"after"`
}

// AttackPathDiff compares reachable modeled attack techniques.
type AttackPathDiff struct {
	Added        []PathSummary     `json:"added"`
	Removed      []PathSummary     `json:"removed"`
	ChangedState []PathStateChange `json:"changedState"`
}

// ControlChange records changed observed mitigating-control metadata.
type ControlChange struct {
	Ref    snapshot.ObjectRef       `json:"ref"`
	Before snapshot.SecurityControl `json:"before"`
	After  snapshot.SecurityControl `json:"after"`
}

// ControlDiff compares security controls separately from generic objects.
type ControlDiff struct {
	Added    []snapshot.SecurityControl `json:"added"`
	Removed  []snapshot.SecurityControl `json:"removed"`
	Modified []ControlChange            `json:"modified"`
}

// ScoreDelta preserves exact before/after arithmetic.
type ScoreDelta struct {
	Key            string        `json:"key"`
	Before         int           `json:"before"`
	After          int           `json:"after"`
	Delta          int           `json:"delta"`
	BeforeSeverity risk.Severity `json:"beforeSeverity"`
	AfterSeverity  risk.Severity `json:"afterSeverity"`
}

// RiskDiff compares cluster and scoped aggregate scores.
type RiskDiff struct {
	Cluster    ScoreDelta   `json:"cluster"`
	Identities []ScoreDelta `json:"identities"`
	Namespaces []ScoreDelta `json:"namespaces"`
}

// Summary provides counts for fast CLI and TUI presentation.
type Summary struct {
	ObjectsAdded             int `json:"objectsAdded"`
	ObjectsRemoved           int `json:"objectsRemoved"`
	ObjectsModified          int `json:"objectsModified"`
	IdentitiesAdded          int `json:"identitiesAdded"`
	IdentitiesRemoved        int `json:"identitiesRemoved"`
	PermissionsAdded         int `json:"permissionsAdded"`
	PermissionsRemoved       int `json:"permissionsRemoved"`
	PermissionGrantsChanged  int `json:"permissionGrantsChanged"`
	DangerousCapabilitiesNew int `json:"dangerousCapabilitiesNew"`
	FindingsAdded            int `json:"findingsAdded"`
	FindingsRemoved          int `json:"findingsRemoved"`
	AttackPathsAdded         int `json:"attackPathsAdded"`
	AttackPathsRemoved       int `json:"attackPathsRemoved"`
	AttackPathStatesChanged  int `json:"attackPathStatesChanged"`
	ControlsChanged          int `json:"controlsChanged"`
	ClusterRiskDelta         int `json:"clusterRiskDelta"`
}

// Warning keeps incomplete or bounded analysis visible.
type Warning struct {
	Side    string `json:"side"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is a deterministic semantic comparison of two snapshots.
type Result struct {
	SchemaVersion         string                      `json:"schemaVersion"`
	BeforeSemanticDigest  string                      `json:"beforeSemanticDigest"`
	AfterSemanticDigest   string                      `json:"afterSemanticDigest"`
	Complete              bool                        `json:"complete"`
	Truncated             bool                        `json:"truncated"`
	Summary               Summary                     `json:"summary"`
	Objects               ObjectDiff                  `json:"objects"`
	Identities            IdentityDiff                `json:"identities"`
	Permissions           []PermissionDiff            `json:"permissions"`
	DangerousCapabilities []DangerousCapabilityChange `json:"dangerousCapabilities"`
	Findings              FindingDiff                 `json:"findings"`
	AttackPaths           AttackPathDiff              `json:"attackPaths"`
	Controls              ControlDiff                 `json:"controls"`
	Risk                  RiskDiff                    `json:"risk"`
	Warnings              []Warning                   `json:"warnings"`
}
