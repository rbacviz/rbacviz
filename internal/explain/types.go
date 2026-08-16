// Package explain builds deterministic, evidence-backed explanations of how
// Kubernetes identities receive effective RBAC permissions.
package explain

import (
	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the machine-readable explanation contract.
	ResultSchemaVersion = "1.0"
	// ModelVersion identifies the correlation and prioritization model.
	ModelVersion = "1.0.0"
)

// Status distinguishes actionable access from conditional, blocked, and
// configuration-only observations.
type Status string

const (
	// StatusActionable means an unblocked confirmed or likely attack path uses this grant.
	StatusActionable Status = "ACTIONABLE"
	// StatusConditional means exploitation still requires an unobserved condition.
	StatusConditional Status = "CONDITIONAL"
	// StatusBlocked means every correlated path is blocked by an evaluated control.
	StatusBlocked Status = "BLOCKED"
	// StatusObservation means no attack path is currently correlated with the grant.
	StatusObservation Status = "OBSERVATION"
)

// Priority is an operator-facing remediation queue priority. P0 is reserved
// for urgent actionable access; it is not a probability.
type Priority string

const (
	// PriorityP0 is reserved for urgent, actionable critical access.
	PriorityP0 Priority = "P0"
	// PriorityP1 identifies critical or directly actionable high-impact access.
	PriorityP1 Priority = "P1"
	// PriorityP2 identifies planned remediation or prerequisite validation.
	PriorityP2 Priority = "P2"
	// PriorityP3 identifies lower-priority observations and blocked access.
	PriorityP3 Priority = "P3"
)

// CapabilitySummary is one normalized effective permission plus the exact
// independent grants and security signals that apply to it.
type CapabilitySummary struct {
	Verb           string                `json:"verb"`
	APIGroup       string                `json:"apiGroup,omitempty"`
	Resource       string                `json:"resource,omitempty"`
	Subresource    string                `json:"subresource,omitempty"`
	ResourceNames  []string              `json:"resourceNames"`
	NonResourceURL string                `json:"nonResourceURL,omitempty"`
	Scope          permission.Scope      `json:"scope"`
	Namespace      string                `json:"namespace,omitempty"`
	GrantIDs       []string              `json:"grantIds"`
	FindingIDs     []string              `json:"findingIds"`
	PathIDs        []string              `json:"pathIds"`
	Severity       analysis.Severity     `json:"severity"`
	Confidence     attackpath.Confidence `json:"confidence"`
	Risk           int                   `json:"risk"`
}

// Analysis explains why a grant matters and what an operator should verify or
// change. Recommendations come only from evidence-backed rules.
type Analysis struct {
	Priority        Priority              `json:"priority"`
	Status          Status                `json:"status"`
	Severity        analysis.Severity     `json:"severity"`
	Confidence      attackpath.Confidence `json:"confidence"`
	MaxPathRisk     int                   `json:"maxPathRisk"`
	RootCause       string                `json:"rootCause"`
	Impact          string                `json:"impact,omitempty"`
	Recommendations []string              `json:"recommendations"`
	Verification    []string              `json:"verification"`
	Preconditions   []string              `json:"preconditions"`
	Mitigations     []string              `json:"mitigations"`
}

// AccessExplanation is one root-cause grant chain. Multiple effective
// capabilities remain grouped under the binding/subject pair that created
// them, so one broad binding is not presented as dozens of independent issues.
type AccessExplanation struct {
	ID               string               `json:"id"`
	RootCauseKey     string               `json:"rootCauseKey"`
	Workloads        []snapshot.ObjectRef `json:"workloads"`
	Subject          permission.Identity  `json:"subject"`
	Binding          snapshot.ObjectRef   `json:"binding"`
	Role             snapshot.ObjectRef   `json:"role"`
	AggregationChain []snapshot.ObjectRef `json:"aggregationChain"`
	Capabilities     []CapabilitySummary  `json:"capabilities"`
	FindingIDs       []string             `json:"findingIds"`
	RuleIDs          []string             `json:"ruleIds"`
	PathIDs          []string             `json:"pathIds"`
	RelatedIDs       []string             `json:"relatedIds"`
	Analysis         Analysis             `json:"analysis"`
}

// Warning preserves bounded-analysis limitations without treating missing data
// as proof that a grant or attack path is absent.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is shared by the TUI and report pipeline.
type Result struct {
	SchemaVersion  string              `json:"schemaVersion"`
	ModelVersion   string              `json:"modelVersion"`
	Complete       bool                `json:"complete"`
	Explanations   []AccessExplanation `json:"explanations"`
	Warnings       []Warning           `json:"warnings"`
	selectionIndex map[string][]int
	rootCauseIndex map[string][]int
}

// Lookup returns deterministic explanations related to one TUI/report item.
func (result Result) Lookup(selectionID string) []AccessExplanation {
	if indexes, ok := result.selectionIndex[selectionID]; ok {
		return result.at(indexes)
	}
	values := make([]AccessExplanation, 0)
	for _, value := range result.Explanations {
		if value.ID == selectionID || contains(value.RelatedIDs, selectionID) {
			values = append(values, value)
		}
	}
	return values
}

// ByRootCause returns explanations for one report root-cause key.
func (result Result) ByRootCause(key string) []AccessExplanation {
	if indexes, ok := result.rootCauseIndex[key]; ok {
		return result.at(indexes)
	}
	values := make([]AccessExplanation, 0)
	for _, value := range result.Explanations {
		if value.RootCauseKey == key {
			values = append(values, value)
		}
	}
	return values
}

func (result Result) at(indexes []int) []AccessExplanation {
	values := make([]AccessExplanation, 0, len(indexes))
	for _, index := range indexes {
		if index >= 0 && index < len(result.Explanations) {
			values = append(values, result.Explanations[index])
		}
	}
	return values
}

func (result *Result) buildIndexes() {
	result.selectionIndex = make(map[string][]int)
	result.rootCauseIndex = make(map[string][]int)
	for index, value := range result.Explanations {
		result.selectionIndex[value.ID] = append(result.selectionIndex[value.ID], index)
		for _, relatedID := range value.RelatedIDs {
			result.selectionIndex[relatedID] = append(result.selectionIndex[relatedID], index)
		}
		result.rootCauseIndex[value.RootCauseKey] = append(result.rootCauseIndex[value.RootCauseKey], index)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
