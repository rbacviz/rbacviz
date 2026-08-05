// Package snapshot owns the portable, versioned input consumed by analysis.
package snapshot

const (
	// SchemaVersion is the current snapshot wire-format major and minor version.
	SchemaVersion = "1.0"
)

// Snapshot is a credential-free, deterministic description of security-relevant
// Kubernetes state. Slice fields are canonicalized before persistence.
type Snapshot struct {
	SchemaVersion    string            `json:"schemaVersion"`
	ToolVersion      string            `json:"toolVersion"`
	Metadata         Metadata          `json:"metadata"`
	APIResources     []APIResource     `json:"apiResources"`
	Identities       []Identity        `json:"identities"`
	Roles            []Role            `json:"roles"`
	Bindings         []Binding         `json:"bindings"`
	ServiceAccounts  []ServiceAccount  `json:"serviceAccounts"`
	Workloads        []Workload        `json:"workloads"`
	Assets           []Asset           `json:"assets"`
	SecurityControls []SecurityControl `json:"securityControls"`
	Warnings         []Warning         `json:"collectionWarnings"`
}

// Metadata describes how and when collection happened without persisting
// kubeconfig paths, endpoints, tokens, or credentials.
type Metadata struct {
	CollectedAt        string `json:"collectedAt"`
	Context            string `json:"context,omitempty"`
	Namespace          string `json:"namespace,omitempty"`
	AllNamespaces      bool   `json:"allNamespaces"`
	Complete           bool   `json:"complete"`
	ClusterFingerprint string `json:"clusterFingerprint,omitempty"`
}

// ObjectRef is the portable identity of a Kubernetes object.
type ObjectRef struct {
	APIGroup  string `json:"apiGroup,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

// KeyValue replaces persisted maps so ordering and future schema changes stay explicit.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// APIResource records the discovery information needed for scope-aware analysis.
type APIResource struct {
	GroupVersion string   `json:"groupVersion"`
	APIGroup     string   `json:"apiGroup,omitempty"`
	Version      string   `json:"version"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Namespaced   bool     `json:"namespaced"`
	Verbs        []string `json:"verbs"`
}

// IdentityKind is one of the Kubernetes RBAC subject kinds.
type IdentityKind string

const (
	// IdentityUser is a directly bound Kubernetes user subject.
	IdentityUser IdentityKind = "User"
	// IdentityGroup is a directly bound Kubernetes group subject.
	IdentityGroup IdentityKind = "Group"
	// IdentityServiceAccount is a namespaced Kubernetes ServiceAccount subject.
	IdentityServiceAccount IdentityKind = "ServiceAccount"
)

// Identity is a subject discovered from bindings or ServiceAccount objects.
type Identity struct {
	ID         string       `json:"id"`
	Kind       IdentityKind `json:"kind"`
	Namespace  string       `json:"namespace,omitempty"`
	Name       string       `json:"name"`
	Provenance []ObjectRef  `json:"provenance"`
}

// PolicyRule is the original Kubernetes RBAC rule plus a stable semantic ID.
type PolicyRule struct {
	ID              string   `json:"id"`
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

// LabelSelector is the portable subset used by aggregated ClusterRoles.
type LabelSelector struct {
	MatchLabels      []KeyValue            `json:"matchLabels"`
	MatchExpressions []SelectorRequirement `json:"matchExpressions"`
}

// SelectorRequirement mirrors metav1.LabelSelectorRequirement.
type SelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// Role represents both Role and ClusterRole.
type Role struct {
	ID                   string          `json:"id"`
	Ref                  ObjectRef       `json:"ref"`
	Labels               []KeyValue      `json:"labels"`
	Rules                []PolicyRule    `json:"rules"`
	AggregationSelectors []LabelSelector `json:"aggregationSelectors"`
}

// Subject is a canonical binding subject.
type Subject struct {
	Kind      IdentityKind `json:"kind"`
	APIGroup  string       `json:"apiGroup,omitempty"`
	Namespace string       `json:"namespace,omitempty"`
	Name      string       `json:"name"`
}

// Binding represents RoleBinding and ClusterRoleBinding.
type Binding struct {
	ID       string     `json:"id"`
	Ref      ObjectRef  `json:"ref"`
	Labels   []KeyValue `json:"labels"`
	RoleRef  ObjectRef  `json:"roleRef"`
	Subjects []Subject  `json:"subjects"`
}

// ServiceAccount stores only security-relevant metadata.
type ServiceAccount struct {
	ID                    string     `json:"id"`
	Ref                   ObjectRef  `json:"ref"`
	Labels                []KeyValue `json:"labels"`
	AutomountServiceToken *bool      `json:"automountServiceAccountToken,omitempty"`
}

// OwnerReference preserves workload relationships.
type OwnerReference struct {
	Ref        ObjectRef `json:"ref"`
	Controller bool      `json:"controller"`
}

// VolumeReference records a metadata-only relationship from a Pod spec.
type VolumeReference struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Target    string `json:"target,omitempty"`
}

// Workload stores the Pod security information required by later graph analysis.
type Workload struct {
	ID                    string            `json:"id"`
	Ref                   ObjectRef         `json:"ref"`
	Labels                []KeyValue        `json:"labels"`
	Owners                []OwnerReference  `json:"owners"`
	ServiceAccountName    string            `json:"serviceAccountName"`
	AutomountServiceToken *bool             `json:"automountServiceAccountToken,omitempty"`
	HostNetwork           bool              `json:"hostNetwork"`
	HostPID               bool              `json:"hostPID"`
	HostIPC               bool              `json:"hostIPC"`
	PrivilegedContainers  []string          `json:"privilegedContainers"`
	Images                []string          `json:"images"`
	Volumes               []VolumeReference `json:"volumes"`
}

// Asset is credential-free metadata for a security-relevant Kubernetes object.
// Secret payload fields intentionally do not exist in this schema.
type Asset struct {
	ID         string     `json:"id"`
	Ref        ObjectRef  `json:"ref"`
	Labels     []KeyValue `json:"labels"`
	AssetType  string     `json:"assetType"`
	SecretType string     `json:"secretType,omitempty"`
}

// SecurityControl is an observation, not a claim that arbitrary policy code
// has been semantically evaluated.
type SecurityControl struct {
	ID               string     `json:"id"`
	Ref              ObjectRef  `json:"ref"`
	ControlType      string     `json:"controlType"`
	Mode             string     `json:"mode,omitempty"`
	Details          []KeyValue `json:"details"`
	SemanticsUnknown bool       `json:"semanticsUnknown"`
}

// Warning records one failed or incomplete collection operation.
type Warning struct {
	Resource string `json:"resource"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}
