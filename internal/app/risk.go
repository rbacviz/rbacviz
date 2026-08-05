package app

import (
	"context"
	"fmt"

	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// RiskAnalyzer is the application boundary shared by CLI and future TUI.
type RiskAnalyzer struct{ engine *risk.Engine }

// NewRiskAnalyzer initializes the transparent risk model over one snapshot.
func NewRiskAnalyzer(value snapshot.Snapshot) (*RiskAnalyzer, error) {
	engine, err := risk.New(value)
	if err != nil {
		return nil, fmt.Errorf("initialize risk engine: %w", err)
	}
	return &RiskAnalyzer{engine: engine}, nil
}

// Analyze returns deterministic path and aggregate scores.
func (analyzer *RiskAnalyzer) Analyze(ctx context.Context, query risk.Query) (risk.Result, error) {
	return analyzer.engine.Analyze(ctx, query)
}
