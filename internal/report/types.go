// Package report builds a human-oriented security report from the same
// immutable analysis results used by the CLI and TUI.
package report

import (
	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/explain"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/remediation"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the machine-readable report contract.
	ResultSchemaVersion = "1.2"
	// ModelVersion identifies the report grouping and prioritization model.
	ModelVersion = "1.2.0"
)

// Options bounds the analyses used to construct a report.
type Options struct {
	Namespace     string
	MaxIssues     int
	MaxCandidates int
	MaxPaths      int
	MaxExpanded   int
	Baseline      *baseline.Document
	EvaluatedAt   string
}

// Inventory is a credential-free summary of the analyzed snapshot.
type Inventory struct {
	APIResources       int `json:"apiResources"`
	Identities         int `json:"identities"`
	Roles              int `json:"roles"`
	Bindings           int `json:"bindings"`
	ServiceAccounts    int `json:"serviceAccounts"`
	Workloads          int `json:"workloads"`
	Assets             int `json:"assets"`
	SecurityControls   int `json:"securityControls"`
	CollectionWarnings int `json:"collectionWarnings"`
}

// Actionability distinguishes observed attack paths from configuration-only
// findings and paths that require conditions or are blocked by known controls.
type Actionability string

const (
	// ActionabilityActionable means an unblocked confirmed or likely path exists.
	ActionabilityActionable Actionability = "ACTIONABLE"
	// ActionabilityConditional means exploitation requires an unobserved condition.
	ActionabilityConditional Actionability = "CONDITIONAL"
	// ActionabilityBlocked means evaluated controls block every correlated path.
	ActionabilityBlocked Actionability = "BLOCKED"
	// ActionabilityObservation is a finding without a correlated attack path.
	ActionabilityObservation Actionability = "OBSERVATION"
	// ActionabilityAccepted identifies a reviewed, non-expired exception. The
	// issue remains visible but is removed from active posture aggregation.
	ActionabilityAccepted Actionability = "ACCEPTED"
)

// Priority is a remediation queue priority, deliberately separate from impact
// severity and from the posture-oriented risk index.
type Priority string

const (
	// PriorityP0 is an urgent actionable critical issue with a measured fix.
	PriorityP0 Priority = "P0"
	// PriorityP1 is a critical or directly remediable high-priority issue.
	PriorityP1 Priority = "P1"
	// PriorityP2 requires planned remediation or prerequisite validation.
	PriorityP2 Priority = "P2"
	// PriorityP3 is a lower-priority observation or blocked path.
	PriorityP3 Priority = "P3"
)

// Summary is the executive overview. Raw counts and grouped root causes are
// both retained so a report never disguises presentation deduplication.
type Summary struct {
	RiskModelVersion         string        `json:"riskModelVersion"`
	RiskIndex                int           `json:"riskIndex"`
	RiskSeverity             risk.Severity `json:"riskSeverity"`
	RiskFamilies             int           `json:"riskFamilies"`
	ContributingRiskFamilies int           `json:"contributingRiskFamilies"`
	RawFindings              int           `json:"rawFindings"`
	DetectedRootCauses       int           `json:"detectedRootCauses"`
	RootCauses               int           `json:"rootCauses"`
	IncludedIssues           int           `json:"includedIssues"`
	OmittedIssues            int           `json:"omittedIssues"`
	AttackPaths              int           `json:"attackPaths"`
	ActionablePaths          int           `json:"actionablePaths"`
	ConditionalPaths         int           `json:"conditionalPaths"`
	BlockedPaths             int           `json:"blockedPaths"`
	RecommendedFixes         int           `json:"recommendedFixes"`
	PriorityP0               int           `json:"priorityP0"`
	PriorityP1               int           `json:"priorityP1"`
	PriorityP2               int           `json:"priorityP2"`
	PriorityP3               int           `json:"priorityP3"`
	AcceptedExceptions       int           `json:"acceptedExceptions"`
	ExpiredExceptions        int           `json:"expiredExceptions"`
	UnmatchedExceptions      int           `json:"unmatchedExceptions"`
}

// Fix is one virtual remediation candidate already measured by the remediation
// engine. It is advice only; the report contains no apply operation.
type Fix struct {
	ID                 string                  `json:"id"`
	Title              string                  `json:"title"`
	Kind               remediation.Kind        `json:"kind"`
	Disposition        remediation.Disposition `json:"disposition"`
	Change             remediation.Change      `json:"change"`
	Reason             string                  `json:"reason"`
	RiskBefore         int                     `json:"riskBefore"`
	RiskAfter          int                     `json:"riskAfter"`
	RiskDelta          int                     `json:"riskDelta"`
	RemovedPaths       int                     `json:"removedPaths"`
	BlockedPaths       int                     `json:"blockedPaths"`
	RemainingPaths     int                     `json:"remainingPaths"`
	LostCapabilities   int                     `json:"lostCapabilities"`
	AffectedIdentities []permission.Identity   `json:"affectedIdentities"`
	Verification       []string                `json:"verification"`
	Caution            string                  `json:"caution"`
}

// Issue groups correlated findings and attack paths around one observed root
// cause, normally an exact binding/subject grant or one Kubernetes object.
type Issue struct {
	ID                 string                      `json:"id"`
	RootCauseKey       string                      `json:"rootCauseKey"`
	RootCause          string                      `json:"rootCause"`
	Title              string                      `json:"title"`
	Priority           Priority                    `json:"priority"`
	Severity           analysis.Severity           `json:"severity"`
	Confidence         attackpath.Confidence       `json:"confidence"`
	Actionability      Actionability               `json:"actionability"`
	MaxPathRisk        int                         `json:"maxPathRisk"`
	SecurityImpact     string                      `json:"securityImpact"`
	AffectedIdentities []permission.Identity       `json:"affectedIdentities"`
	AffectedObjects    []snapshot.ObjectRef        `json:"affectedObjects"`
	FindingIDs         []string                    `json:"findingIds"`
	RuleIDs            []string                    `json:"ruleIds"`
	PathIDs            []string                    `json:"pathIds"`
	RiskFamilyIDs      []string                    `json:"riskFamilyIds"`
	Recommendations    []string                    `json:"recommendations"`
	Evidence           []string                    `json:"evidence"`
	AccessExplanations []explain.AccessExplanation `json:"accessExplanations"`
	Fixes              []Fix                       `json:"fixes"`
}

// Exception is an auditable baseline entry plus every correlated issue. An
// accepted exception never deletes the underlying signals from the report.
type Exception struct {
	Suppression   baseline.Suppression `json:"suppression"`
	State         baseline.State       `json:"state"`
	FindingIDs    []string             `json:"findingIds"`
	RiskFamilyIDs []string             `json:"riskFamilyIds"`
	RootCauseKeys []string             `json:"rootCauseKeys"`
	Issues        []Issue              `json:"issues"`
}

// BaselineSummary records the policy contract and evaluation time used.
type BaselineSummary struct {
	SchemaVersion string           `json:"schemaVersion"`
	Profile       baseline.Profile `json:"profile"`
	EvaluatedAt   string           `json:"evaluatedAt"`
	Entries       int              `json:"entries"`
}

// Warning preserves every bounded or incomplete-analysis limitation.
type Warning struct {
	Source  string `json:"source"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is the single versioned source for Markdown and JSON reports.
type Result struct {
	SchemaVersion       string           `json:"schemaVersion"`
	ModelVersion        string           `json:"modelVersion"`
	ToolVersion         string           `json:"toolVersion"`
	SnapshotCollected   string           `json:"snapshotCollectedAt"`
	ClusterContext      string           `json:"clusterContext,omitempty"`
	ClusterFingerprint  string           `json:"clusterFingerprint,omitempty"`
	Namespace           string           `json:"namespace,omitempty"`
	Complete            bool             `json:"complete"`
	Truncated           bool             `json:"truncated"`
	Inventory           Inventory        `json:"inventory"`
	Summary             Summary          `json:"summary"`
	Issues              []Issue          `json:"issues"`
	Baseline            *BaselineSummary `json:"baseline,omitempty"`
	AcceptedExceptions  []Exception      `json:"acceptedExceptions"`
	ExpiredExceptions   []Exception      `json:"expiredExceptions"`
	UnmatchedExceptions []Exception      `json:"unmatchedExceptions"`
	Warnings            []Warning        `json:"warnings"`
}
