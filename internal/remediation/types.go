// Package remediation generates and virtually evaluates advisory Kubernetes
// security changes. It has no Kubernetes client and cannot apply changes.
package remediation

import (
	"github.com/rbacviz/rbacviz/internal/attackpath"
	semanticdiff "github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the machine-readable remediation contract.
	ResultSchemaVersion = "1.0"
	// ModelVersion identifies candidate generation and ranking constants.
	ModelVersion = "1.0.0"
)

// Options bounds candidate generation and the analyses used for simulation.
type Options struct {
	Identity         *permission.Identity
	Namespace        string
	MaxCandidates    int
	MaxPaths         int
	MaxExpanded      int
	IncludeDominated bool
	IncludeDiff      bool
}

// Kind is a structured virtual change supported by the first model.
type Kind string

const (
	// KindRemoveSubject removes one exact subject from one observed binding.
	KindRemoveSubject Kind = "REMOVE_SUBJECT_GRANT"
	// KindNarrowRule removes one explicit verb from one source policy rule.
	KindNarrowRule Kind = "NARROW_ROLE_RULE"
	// KindEnforcePSA adds or replaces a namespace restricted PSA observation.
	KindEnforcePSA Kind = "ENFORCE_PSA_RESTRICTED"
)

// Disposition states whether a simulated candidate is recommended.
type Disposition string

const (
	// DispositionRecommended marks a measurable Pareto-optimal candidate.
	DispositionRecommended Disposition = "RECOMMENDED"
	// DispositionDominated marks a measurable but Pareto-dominated candidate.
	DispositionDominated Disposition = "DOMINATED"
	// DispositionIneffective marks a proposal with no modeled security benefit.
	DispositionIneffective Disposition = "INEFFECTIVE"
)

// Change is the complete, credential-free virtual edit description.
type Change struct {
	Kind         Kind               `json:"kind"`
	Ref          snapshot.ObjectRef `json:"ref"`
	Subject      *snapshot.Subject  `json:"subject,omitempty"`
	PolicyRuleID string             `json:"policyRuleId,omitempty"`
	Verb         string             `json:"verb,omitempty"`
	Namespace    string             `json:"namespace,omitempty"`
	Before       string             `json:"before,omitempty"`
	After        string             `json:"after,omitempty"`
}

// LostCapability is one effective permission removed by the proposal.
type LostCapability struct {
	Identity   permission.Identity     `json:"identity"`
	Capability semanticdiff.Capability `json:"capability"`
}

// SecurityBenefit exposes every additive ranking input.
type SecurityBenefit struct {
	RemovedCriticalPaths int `json:"removedCriticalPaths"`
	RemovedHighPaths     int `json:"removedHighPaths"`
	RemovedMediumPaths   int `json:"removedMediumPaths"`
	BlockedPaths         int `json:"blockedPaths"`
	ClusterRiskReduction int `json:"clusterRiskReduction"`
	ScopedRiskReduction  int `json:"scopedRiskReduction"`
	Total                int `json:"total"`
}

// OperationalCost exposes the estimated blast radius of a candidate.
type OperationalCost struct {
	LostCapabilities      int `json:"lostCapabilities"`
	AffectedIdentities    int `json:"affectedIdentities"`
	OperationalComplexity int `json:"operationalComplexity"`
	UncertaintyPenalty    int `json:"uncertaintyPenalty"`
	Total                 int `json:"total"`
}

// Ranking is the deterministic benefit/cost explanation.
type Ranking struct {
	Rank             int  `json:"rank"`
	BenefitCostBasis int  `json:"benefitCostBasisPoints"`
	ParetoOptimal    bool `json:"paretoOptimal"`
}

// Impact is the measured result of one complete virtual re-analysis.
type Impact struct {
	RemovedPathIDs         []string              `json:"removedPathIds"`
	BlockedPathIDs         []string              `json:"blockedPathIds"`
	RemainingAttackPaths   int                   `json:"remainingAttackPaths"`
	LostCapabilities       []LostCapability      `json:"lostCapabilities"`
	AffectedIdentities     []permission.Identity `json:"affectedIdentities"`
	UnresolvedGrantChanges int                   `json:"unresolvedGrantChanges"`
	Risk                   semanticdiff.RiskDiff `json:"risk"`
}

// Candidate is an advisory proposal plus its measured impact and ranking.
type Candidate struct {
	ID          string                           `json:"id"`
	Kind        Kind                             `json:"kind"`
	Title       string                           `json:"title"`
	Description string                           `json:"description"`
	Disposition Disposition                      `json:"disposition"`
	Reason      string                           `json:"reason"`
	Change      Change                           `json:"change"`
	PathIDs     []string                         `json:"pathIds"`
	Targets     []attackpath.PrivilegeTargetType `json:"targets"`
	Benefit     SecurityBenefit                  `json:"benefit"`
	Cost        OperationalCost                  `json:"cost"`
	Ranking     Ranking                          `json:"ranking"`
	Impact      Impact                           `json:"impact"`
	Diff        *semanticdiff.Result             `json:"diff,omitempty"`
	actionKey   string
}

// Warning keeps bounded or incomplete analysis explicit.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Summary supports concise CLI and TUI presentation.
type Summary struct {
	Generated      int `json:"generated"`
	Evaluated      int `json:"evaluated"`
	Recommended    int `json:"recommended"`
	Dominated      int `json:"dominated"`
	Ineffective    int `json:"ineffective"`
	BestRiskBefore int `json:"clusterRiskBefore"`
	BestRiskAfter  int `json:"bestClusterRiskAfter"`
}

// Result is a deterministic set of fully simulated remediation candidates.
type Result struct {
	SchemaVersion string              `json:"schemaVersion"`
	ModelVersion  string              `json:"modelVersion"`
	Complete      bool                `json:"complete"`
	Truncated     bool                `json:"truncated"`
	Summary       Summary             `json:"summary"`
	Candidates    []Candidate         `json:"candidates"`
	Warnings      []Warning           `json:"warnings"`
	BaselineRisk  risk.AggregateScore `json:"baselineRisk"`
}
