package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/remediation"
	"github.com/rbacviz/rbacviz/internal/risk"
)

func loadSnapshotCmd(ctx context.Context, load SnapshotLoader) tea.Cmd {
	return func() tea.Msg {
		if load == nil {
			return loadErrorMsg{err: fmt.Errorf("snapshot loader is not configured")}
		}
		value, err := load(ctx)
		if err != nil {
			return loadErrorMsg{err: err}
		}
		return snapshotLoadedMsg{value: value}
	}
}

func loadGraphCmd(ctx context.Context, dataset Dataset) tea.Cmd {
	return func() tea.Msg {
		if err := ctx.Err(); err != nil {
			return loadErrorMsg{err: err}
		}
		analyzer, err := app.NewGraphAnalyzer(dataset.Snapshot)
		if err != nil {
			return loadErrorMsg{err: err}
		}
		nodes := analyzer.Select(graphmodel.Selector{})
		return graphLoadedMsg{stats: analyzer.Stats(), nodes: nodes}
	}
}

func loadFindingsCmd(ctx context.Context, dataset Dataset) tea.Cmd {
	return func() tea.Msg {
		analyzer, err := app.NewFindingsAnalyzer(dataset.Snapshot)
		if err != nil {
			return loadErrorMsg{err: err}
		}
		value, err := analyzer.Analyze(ctx)
		if err != nil {
			return loadErrorMsg{err: err}
		}
		return findingsLoadedMsg{value: value}
	}
}

func loadPathsCmd(ctx context.Context, dataset Dataset) tea.Cmd {
	return func() tea.Msg {
		analyzer, err := app.NewAttackPathAnalyzer(dataset.Snapshot)
		if err != nil {
			return pathLoadErrorMsg{err: err}
		}
		value, err := analyzer.Analyze(ctx, attackpath.Query{Top: 250, MaxExpanded: 100000})
		if err != nil {
			return pathLoadErrorMsg{err: err}
		}
		return pathsLoadedMsg{value: value}
	}
}

func loadRiskCmd(ctx context.Context, dataset Dataset) tea.Cmd {
	return func() tea.Msg {
		analyzer, err := app.NewRiskAnalyzer(dataset.Snapshot)
		if err != nil {
			return loadErrorMsg{err: err}
		}
		value, err := analyzer.Analyze(ctx, risk.Query{MaxPaths: 10000, MaxExpanded: 100000})
		if err != nil {
			return loadErrorMsg{err: err}
		}
		return riskLoadedMsg{value: value}
	}
}

func loadRemediationCmd(ctx context.Context, dataset Dataset) tea.Cmd {
	return func() tea.Msg {
		value, err := app.GenerateRemediations(ctx, dataset.Snapshot, remediation.Options{MaxCandidates: 100, MaxPaths: 10000, MaxExpanded: 100000})
		if err != nil {
			return remediationLoadErrorMsg{err: err}
		}
		return remediationLoadedMsg{value: value}
	}
}
