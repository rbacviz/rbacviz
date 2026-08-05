package app

import (
	"context"

	semanticdiff "github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/remediation"
	"github.com/rbacviz/rbacviz/internal/simulate"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// CompareSnapshots is the application boundary shared by CLI and future TUI.
func CompareSnapshots(ctx context.Context, before, after snapshot.Snapshot, options semanticdiff.Options) (semanticdiff.Result, error) {
	return semanticdiff.Compare(ctx, before, after, options)
}

// SimulateManifests overlays proposed manifests in memory and measures impact.
func SimulateManifests(ctx context.Context, base snapshot.Snapshot, manifests []simulate.Manifest, options simulate.Options) (simulate.Result, error) {
	return simulate.Run(ctx, base, manifests, options)
}

// GenerateRemediations virtually evaluates advisory changes without exposing
// a cluster mutation interface.
func GenerateRemediations(ctx context.Context, base snapshot.Snapshot, options remediation.Options) (remediation.Result, error) {
	return remediation.Generate(ctx, base, options)
}
