package risk

import (
	"context"
	"fmt"
	"sort"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	defaultMaxPaths    = 10000
	defaultMaxExpanded = 100000
)

// Engine scores one immutable canonical snapshot through the attack-path boundary.
type Engine struct {
	input snapshot.Snapshot
	paths *attackpath.Engine
}

// New validates and indexes the risk input.
func New(input snapshot.Snapshot) (*Engine, error) {
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return nil, fmt.Errorf("canonicalize risk input: %w", err)
	}
	pathEngine, err := attackpath.New(canonical)
	if err != nil {
		return nil, fmt.Errorf("initialize attack paths for risk: %w", err)
	}
	return &Engine{input: canonical, paths: pathEngine}, nil
}

// Analyze scores bounded paths and builds deterministic rollups.
func (engine *Engine) Analyze(ctx context.Context, query Query) (Result, error) {
	if query.MaxPaths <= 0 {
		query.MaxPaths = defaultMaxPaths
	}
	if query.MaxExpanded <= 0 {
		query.MaxExpanded = defaultMaxExpanded
	}
	pathResult, err := engine.paths.Analyze(ctx, attackpath.Query{
		From: query.From, Top: query.MaxPaths, MaxExpanded: query.MaxExpanded,
	})
	if err != nil {
		return Result{}, err
	}
	scores := make([]PathScore, 0, len(pathResult.Paths))
	for _, path := range pathResult.Paths {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		score := scorePath(path, engine.input, query.IncludePath)
		if query.Namespace == "" || containsString(score.Namespaces, query.Namespace) {
			scores = append(scores, score)
		}
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].Score != scores[j].Score {
			return scores[i].Score > scores[j].Score
		}
		return scores[i].ID < scores[j].ID
	})
	families := buildRiskFamilies(scores)
	identities, namespaces, cluster := aggregateAll(scores)
	warnings := make([]Warning, 0, len(pathResult.Warnings))
	for _, warning := range pathResult.Warnings {
		warnings = append(warnings, Warning{Code: warning.Code, Message: warning.Message})
	}
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].Code != warnings[j].Code {
			return warnings[i].Code < warnings[j].Code
		}
		return warnings[i].Message < warnings[j].Message
	})
	return Result{
		SchemaVersion: ResultSchemaVersion, ModelVersion: ModelVersion,
		Complete: pathResult.Complete, Truncated: pathResult.Truncated,
		PathScores: scores, RiskFamilies: families, Identities: identities, Namespaces: namespaces,
		Cluster: cluster, Warnings: warnings,
	}, nil
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}
