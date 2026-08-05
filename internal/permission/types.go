// Package permission calculates effective Kubernetes RBAC permissions from a
// canonical snapshot. It deliberately models only RBAC authorization; it does
// not claim to reproduce every API-server authorizer.
package permission

import "github.com/rbacviz/rbacviz/internal/snapshot"

// ResultSchemaVersion is the major/minor wire version for permission queries.
const ResultSchemaVersion = "1.0"

// Scope describes where a resource capability can be exercised.
type Scope string

const (
	// ScopeNamespaced is limited to one namespace or all namespaces.
	ScopeNamespaced Scope = "Namespaced"
	// ScopeCluster applies to cluster-scoped Kubernetes resources.
	ScopeCluster Scope = "Cluster"
	// ScopeNonResource applies to API server paths rather than resources.
	ScopeNonResource Scope = "NonResource"
	// ScopeUnknown is retained when discovery cannot establish resource scope.
	ScopeUnknown Scope = "Unknown"
)

// Identity is the queryable form of a Kubernetes RBAC subject.
type Identity struct {
	Kind      snapshot.IdentityKind `json:"kind"`
	Namespace string                `json:"namespace,omitempty"`
	Name      string                `json:"name"`
}

// Capability is a normalized selector plus every independent grant that
// produces it. Wildcards remain explicit instead of being eagerly expanded.
type Capability struct {
	Verb           string          `json:"verb"`
	APIGroup       string          `json:"apiGroup,omitempty"`
	Resource       string          `json:"resource,omitempty"`
	Subresource    string          `json:"subresource,omitempty"`
	ResourceNames  []string        `json:"resourceNames"`
	NonResourceURL string          `json:"nonResourceURL,omitempty"`
	Scope          Scope           `json:"scope"`
	Namespace      string          `json:"namespace,omitempty"`
	Grants         []GrantEvidence `json:"grants"`
}

// GrantEvidence is the complete RBAC provenance for one capability.
type GrantEvidence struct {
	ID               string               `json:"id"`
	PolicyRuleID     string               `json:"policyRuleId"`
	BindingRef       snapshot.ObjectRef   `json:"bindingRef"`
	RoleRef          snapshot.ObjectRef   `json:"roleRef"`
	SourceRoleRef    snapshot.ObjectRef   `json:"sourceRoleRef"`
	Subject          snapshot.Subject     `json:"subject"`
	OriginalRule     snapshot.PolicyRule  `json:"originalRule"`
	AggregationChain []snapshot.ObjectRef `json:"aggregationChain"`
}

// Warning explains incomplete or ambiguous permission resolution.
type Warning struct {
	Code    string             `json:"code"`
	Message string             `json:"message"`
	Ref     snapshot.ObjectRef `json:"ref,omitempty"`
}

// Result is the versioned result of an identity permission query.
type Result struct {
	SchemaVersion string       `json:"schemaVersion"`
	Complete      bool         `json:"complete"`
	Identity      Identity     `json:"identity"`
	Groups        []string     `json:"groups"`
	Capabilities  []Capability `json:"capabilities"`
	Warnings      []Warning    `json:"warnings"`
}

// Action represents either a resource or non-resource authorization request.
type Action struct {
	Verb           string `json:"verb"`
	APIGroup       string `json:"apiGroup,omitempty"`
	Resource       string `json:"resource,omitempty"`
	Subresource    string `json:"subresource,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ResourceName   string `json:"resourceName,omitempty"`
	NonResourceURL string `json:"nonResourceURL,omitempty"`
}

// SubjectMatch contains all matching capabilities for a directly represented
// RBAC subject. Group membership is never inferred.
type SubjectMatch struct {
	Identity     Identity     `json:"identity"`
	Capabilities []Capability `json:"capabilities"`
}

// WhoCanResult is the versioned result of an action-centric query.
type WhoCanResult struct {
	SchemaVersion string         `json:"schemaVersion"`
	Complete      bool           `json:"complete"`
	Action        Action         `json:"action"`
	Subjects      []SubjectMatch `json:"subjects"`
	Warnings      []Warning      `json:"warnings"`
}

// WhyCanResult returns every independent grant for one identity and action.
type WhyCanResult struct {
	SchemaVersion string       `json:"schemaVersion"`
	Complete      bool         `json:"complete"`
	Identity      Identity     `json:"identity"`
	Groups        []string     `json:"groups"`
	Action        Action       `json:"action"`
	Allowed       bool         `json:"allowed"`
	Capabilities  []Capability `json:"capabilities"`
	Warnings      []Warning    `json:"warnings"`
}
