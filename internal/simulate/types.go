// Package simulate parses proposed Kubernetes manifests and overlays their
// security-relevant metadata onto a snapshot without contacting a cluster.
package simulate

import (
	"github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ResultSchemaVersion versions the offline simulation result.
	ResultSchemaVersion = "1.0"
	// OperationAnnotation opts a manifest into deletion rather than replacement.
	OperationAnnotation = "rbacviz.io/simulate-operation"
)

// Options controls manifest defaults and bounded semantic analysis.
type Options struct {
	DefaultNamespace string
	Diff             diff.Options
}

// Operation is the in-memory action represented by a manifest.
type Operation string

const (
	// OperationUpsert creates or fully replaces relevant object metadata.
	OperationUpsert Operation = "UPSERT"
	// OperationDelete removes a matching object from the simulated snapshot.
	OperationDelete Operation = "DELETE"
)

// Manifest identifies one parsed manifest document without storing its body.
type Manifest struct {
	Source    string             `json:"source"`
	Document  int                `json:"document"`
	Operation Operation          `json:"operation"`
	Ref       snapshot.ObjectRef `json:"ref"`
	Category  string             `json:"category"`
	object    any
}

// AppliedChange is safe to report and never contains Secret payloads.
type AppliedChange struct {
	Source    string             `json:"source"`
	Document  int                `json:"document"`
	Operation Operation          `json:"operation"`
	Ref       snapshot.ObjectRef `json:"ref"`
	Category  string             `json:"category"`
	Existed   bool               `json:"existed"`
}

// Result is the proposed snapshot plus its measured security delta.
type Result struct {
	SchemaVersion   string          `json:"schemaVersion"`
	BaseDigest      string          `json:"baseDigest"`
	SimulatedDigest string          `json:"simulatedDigest"`
	Applied         []AppliedChange `json:"applied"`
	Diff            diff.Result     `json:"diff"`
}
