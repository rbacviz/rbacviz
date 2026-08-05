package app

import (
	"context"
	"fmt"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// AttackPathAnalyzer is the application boundary shared by CLI and future TUI.
type AttackPathAnalyzer struct{ engine *attackpath.Engine }

// NewAttackPathAnalyzer initializes the built-in template engine.
func NewAttackPathAnalyzer(value snapshot.Snapshot) (*AttackPathAnalyzer, error) {
	engine, err := attackpath.New(value)
	if err != nil {
		return nil, fmt.Errorf("initialize attack-path engine: %w", err)
	}
	return &AttackPathAnalyzer{engine: engine}, nil
}

// Analyze returns deterministic bounded attack paths.
func (analyzer *AttackPathAnalyzer) Analyze(ctx context.Context, query attackpath.Query) (attackpath.Result, error) {
	return analyzer.engine.Analyze(ctx, query)
}
