// Package risk assigns deterministic, explainable risk scores to observed
// attack paths and aggregates them without treating object count as risk.
package risk

import (
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
)

const (
	// ResultSchemaVersion versions the machine-readable risk result.
	ResultSchemaVersion = "1.0"
	// ModelVersion identifies the exact scoring constants and aggregation model.
	ModelVersion = "1.0.0"
)

// Severity is derived from a score and is not an independent hidden input.
type Severity string

const (
	// SeverityCritical marks scores from 85 through 100.
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh marks scores from 70 through 84.
	SeverityHigh Severity = "HIGH"
	// SeverityMedium marks scores from 40 through 69.
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow marks scores from 1 through 39.
	SeverityLow Severity = "LOW"
	// SeverityInfo marks a zero score.
	SeverityInfo Severity = "INFO"
)

// FactorName is a stable path scoring dimension.
type FactorName string

const (
	// FactorImpact represents privilege gained.
	FactorImpact FactorName = "IMPACT"
	// FactorExploitability represents modeled effort and prerequisites.
	FactorExploitability FactorName = "EXPLOITABILITY"
	// FactorBlastRadius represents the affected security scope.
	FactorBlastRadius FactorName = "BLAST_RADIUS"
	// FactorExposure represents observed identity usage.
	FactorExposure FactorName = "EXPOSURE"
	// FactorPathQuality represents evidence completeness.
	FactorPathQuality FactorName = "PATH_QUALITY"
	// FactorConfidence maps the categorical evidence state.
	FactorConfidence FactorName = "CONFIDENCE"
)

// Factor exposes one normalized input, its integer weight, contribution, and source.
type Factor struct {
	Name         FactorName `json:"name"`
	Value        int        `json:"value"`
	Weight       int        `json:"weightPercent"`
	Contribution int        `json:"weightedContribution"`
	Source       string     `json:"source"`
}

// Formula exposes the exact integer arithmetic used to obtain a path score.
type Formula struct {
	Expression          string `json:"expression"`
	WeightedTotal       int    `json:"weightedTotal"`
	WeightDivisor       int    `json:"weightDivisor"`
	ScopeFactorBasisPts int    `json:"scopeFactorBasisPoints"`
	MitigationBasisPts  int    `json:"mitigationEffectBasisPoints"`
	Numerator           int64  `json:"numerator"`
	Denominator         int64  `json:"denominator"`
}

// Mitigation summarizes only controls already evaluated by the attack-path engine.
type Mitigation struct {
	EffectBasisPts int      `json:"effectBasisPoints"`
	Blocking       int      `json:"blockingControls"`
	Potential      int      `json:"potentialControls"`
	Observed       int      `json:"observedControls"`
	Reasons        []string `json:"reasons"`
}

// PathScore is the complete explanation for one attack path.
type PathScore struct {
	ID             string                     `json:"id"`
	PathID         string                     `json:"pathId"`
	TemplateID     string                     `json:"templateId"`
	Title          string                     `json:"title"`
	Source         permission.Identity        `json:"source"`
	Target         attackpath.PrivilegeTarget `json:"target"`
	Confidence     attackpath.Confidence      `json:"confidence"`
	Blocked        bool                       `json:"blocked"`
	Namespaces     []string                   `json:"namespaces"`
	Factors        []Factor                   `json:"factors"`
	ScopeFactorBPS int                        `json:"scopeFactorBasisPoints"`
	Mitigation     Mitigation                 `json:"mitigation"`
	Formula        Formula                    `json:"formula"`
	Score          int                        `json:"score"`
	Severity       Severity                   `json:"severity"`
	RiskUnit       string                     `json:"riskUnit"`
	Path           *attackpath.Path           `json:"path,omitempty"`
}

// AggregateKind distinguishes cluster, namespace, and identity rollups.
type AggregateKind string

const (
	// AggregateCluster is the complete bounded cluster rollup.
	AggregateCluster AggregateKind = "CLUSTER"
	// AggregateNamespace is a namespace-specific rollup.
	AggregateNamespace AggregateKind = "NAMESPACE"
	// AggregateIdentity is a source-identity rollup.
	AggregateIdentity AggregateKind = "IDENTITY"
)

// AggregateScore combines distinct semantic risk units with saturation.
type AggregateScore struct {
	Kind                   AggregateKind        `json:"kind"`
	Key                    string               `json:"key"`
	Identity               *permission.Identity `json:"identity,omitempty"`
	Namespace              string               `json:"namespace,omitempty"`
	Score                  int                  `json:"score"`
	Severity               Severity             `json:"severity"`
	PrimaryScore           int                  `json:"primaryScore"`
	AdditionalContribution int                  `json:"additionalContribution"`
	DistinctRiskUnits      int                  `json:"distinctRiskUnits"`
	PathCount              int                  `json:"pathCount"`
	PathIDs                []string             `json:"pathIds"`
	Explanation            string               `json:"explanation"`
}

// Warning preserves analysis gaps that make the score non-exhaustive.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Query provides hard analysis bounds.
type Query struct {
	From        *permission.Identity
	Namespace   string
	MaxPaths    int
	MaxExpanded int
	IncludePath bool
}

// Result is shared by CLI and the future TUI.
type Result struct {
	SchemaVersion string           `json:"schemaVersion"`
	ModelVersion  string           `json:"modelVersion"`
	Complete      bool             `json:"complete"`
	Truncated     bool             `json:"truncated"`
	PathScores    []PathScore      `json:"pathScores"`
	Identities    []AggregateScore `json:"identities"`
	Namespaces    []AggregateScore `json:"namespaces"`
	Cluster       AggregateScore   `json:"cluster"`
	Warnings      []Warning        `json:"warnings"`
}
