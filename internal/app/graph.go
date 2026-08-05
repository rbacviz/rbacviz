package app

import (
	"context"
	"fmt"

	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// GraphAnalyzer is the immutable graph query surface shared by CLI and TUI.
type GraphAnalyzer struct{ graph *graphmodel.Graph }

// NewGraphAnalyzer builds all deterministic indexes from one snapshot.
func NewGraphAnalyzer(value snapshot.Snapshot) (*GraphAnalyzer, error) {
	graph, err := graphmodel.Build(value)
	if err != nil {
		return nil, fmt.Errorf("build permission graph: %w", err)
	}
	return &GraphAnalyzer{graph: graph}, nil
}

// Stats returns stable graph cardinalities.
func (analyzer *GraphAnalyzer) Stats() graphmodel.Stats { return analyzer.graph.Stats() }

// Warnings returns graph construction ambiguities.
func (analyzer *GraphAnalyzer) Warnings() []graphmodel.Warning { return analyzer.graph.Warnings() }

// Select filters indexed graph nodes.
func (analyzer *GraphAnalyzer) Select(selector graphmodel.Selector) []graphmodel.Node {
	return analyzer.graph.Select(selector)
}

// Resolve accepts one exact stable ID or portable key.
func (analyzer *GraphAnalyzer) Resolve(value string) (graphmodel.Node, error) {
	return analyzer.graph.Resolve(value)
}

// Traverse returns bounded reachable nodes.
func (analyzer *GraphAnalyzer) Traverse(ctx context.Context, start string, direction graphmodel.Direction, limits graphmodel.TraversalLimits) (graphmodel.TraversalResult, error) {
	return analyzer.graph.Traverse(ctx, start, direction, limits)
}

// TopKPaths returns bounded weighted loopless paths.
func (analyzer *GraphAnalyzer) TopKPaths(ctx context.Context, from, to string, limits graphmodel.PathLimits) (graphmodel.PathResult, error) {
	return analyzer.graph.TopKPaths(ctx, from, to, limits)
}
