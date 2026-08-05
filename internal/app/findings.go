package app

import (
	"context"
	"fmt"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// FindingsAnalyzer is the application boundary shared by CLI and future TUI.
type FindingsAnalyzer struct{ engine *analysis.Engine }

// NewFindingsAnalyzer initializes the built-in rule engine over one snapshot.
func NewFindingsAnalyzer(value snapshot.Snapshot) (*FindingsAnalyzer, error) {
	engine, err := analysis.New(value)
	if err != nil {
		return nil, fmt.Errorf("initialize findings engine: %w", err)
	}
	return &FindingsAnalyzer{engine: engine}, nil
}

// Analyze evaluates every enabled rule in deterministic order.
func (analyzer *FindingsAnalyzer) Analyze(ctx context.Context) (analysis.Result, error) {
	return analyzer.engine.Analyze(ctx)
}
