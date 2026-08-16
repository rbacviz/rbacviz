package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/explain"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestLoadingPipelineShowsAcceptedSignalsButUsesActiveRisk(t *testing.T) {
	value := loadTestSnapshot(t)
	policy := baseline.Document{SchemaVersion: baseline.SchemaVersion, Profile: baseline.ProfileDevelopment, Suppressions: []baseline.Suppression{{
		ID: "token-minter-reviewed", RootCauseKey: "grant|rbac.authorization.k8s.io|RoleBinding|production|token-minter|user:alice", Subject: "user:alice",
		Reason: "Required by the synthetic deployment workflow", Owner: "platform-security", Expires: "2026-10-01",
	}}}
	model := NewModel(Options{Context: context.Background(), NoColor: true, Baseline: &policy,
		EvaluatedAt: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		Load:        func(context.Context) (snapshot.Snapshot, error) { return value, nil }})
	t.Cleanup(model.Close)
	message := loadSnapshotCmd(model.ctx, model.load)()
	for model.loading && model.err == nil {
		_, command := model.Update(message)
		if command == nil {
			break
		}
		message = command()
	}
	if model.err != nil {
		t.Fatal(model.err)
	}
	if len(model.data.Suppressions.Accepted) != 1 || model.data.Risk.Cluster.Score == 0 || model.data.ActiveRisk.Cluster.Score != 0 {
		t.Fatalf("baseline posture split missing: raw=%+v active=%+v suppressions=%+v", model.data.Risk.Cluster, model.data.ActiveRisk.Cluster, model.data.Suppressions)
	}
	found := false
	for _, item := range model.items[ViewFindings] {
		if strings.Contains(item.Subtitle, "ACCEPTED") && strings.Contains(item.Detail, "remains visible") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("accepted finding was hidden or unlabeled: %+v", model.items[ViewFindings])
	}
}

func TestLoadingPipelineUsesSharedAnalyzers(t *testing.T) {
	value := loadTestSnapshot(t)
	model := NewModel(Options{Context: context.Background(), NoColor: true, Load: func(context.Context) (snapshot.Snapshot, error) { return value, nil }})
	t.Cleanup(model.Close)

	message := loadSnapshotCmd(model.ctx, model.load)()
	for model.loading && model.err == nil {
		_, command := model.Update(message)
		if command == nil {
			break
		}
		message = command()
	}
	if model.err != nil {
		t.Fatalf("loading failed: %v", model.err)
	}
	if model.loading || model.stage != stageReady {
		t.Fatalf("stage = %v, loading = %t", model.stage, model.loading)
	}
	if len(model.data.Findings.Findings) == 0 || len(model.data.Risk.PathScores) == 0 || model.data.Graph.Nodes == 0 || len(model.data.Explanations.Explanations) == 0 {
		t.Fatalf("shared analysis results are missing: %+v", model.data)
	}
	if model.data.Paths.SchemaVersion != "" {
		t.Fatal("detailed paths were materialized eagerly")
	}
	command := model.ensurePaths()
	if command == nil {
		t.Fatal("lazy path command was not created")
	}
	_, _ = model.Update(loadPathsCmd(model.ctx, model.data)())
	if len(model.data.Paths.Paths) == 0 || model.pathsLoading {
		t.Fatal("lazy detailed paths were not loaded")
	}
	command = model.ensureRemediation()
	if command == nil {
		t.Fatal("lazy remediation command was not created")
	}
	_, _ = model.Update(loadRemediationCmd(model.ctx, model.data)())
	if model.data.Remediation.Summary.Evaluated == 0 || model.remediationLoading {
		t.Fatal("lazy remediation candidates were not loaded")
	}
	panel := remediationPanel(model.data, model.data.Paths.Paths[0].ID)
	if !strings.Contains(panel, "Risk") || !strings.Contains(panel, "Advisory only") {
		t.Fatalf("remediation panel = %q", panel)
	}
}

func TestLoadingCanBeCancelled(t *testing.T) {
	started := make(chan struct{})
	model := NewModel(Options{Context: context.Background(), NoColor: true, Load: func(ctx context.Context) (snapshot.Snapshot, error) {
		close(started)
		<-ctx.Done()
		return snapshot.Snapshot{}, ctx.Err()
	}})
	t.Cleanup(model.Close)
	result := make(chan tea.Msg, 1)
	go func() { result <- loadSnapshotCmd(model.ctx, model.load)() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("loader did not start")
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	select {
	case message := <-result:
		_, _ = model.Update(message)
	case <-time.After(time.Second):
		t.Fatal("loader did not observe cancellation")
	}
	if !errors.Is(model.err, context.Canceled) || model.status != "analysis cancelled" {
		t.Fatalf("error = %v, status = %q", model.err, model.status)
	}
}

func TestNavigationSearchFilterAndViewState(t *testing.T) {
	model := readyTestModel(t, 100, 30)
	model.setView(indexOfView(ViewFindings))
	if len(model.activeItems()) == 0 {
		t.Fatal("fixture has no findings")
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	if model.filter[ViewFindings] != 1 {
		t.Fatalf("filter = %d, want 1", model.filter[ViewFindings])
	}
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	if command == nil || model.modal != modalSearch {
		t.Fatal("search did not receive focus")
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("token")})
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.search[ViewFindings] != "token" {
		t.Fatalf("search = %q", model.search[ViewFindings])
	}
	model.setView(indexOfView(ViewNamespaces))
	model.setView(indexOfView(ViewFindings))
	if model.search[ViewFindings] != "token" || model.filter[ViewFindings] != 1 {
		t.Fatal("per-view state was not preserved")
	}
}

func TestLargeListRendersOnlyVisibleWindow(t *testing.T) {
	model := readyTestModel(t, 72, 24)
	values := make([]item, 5000)
	for index := range values {
		values[index] = item{ID: fmt.Sprintf("id-%04d", index), Title: fmt.Sprintf("identity-%04d", index)}
	}
	model.items[ViewIdentities] = values
	model.dirty[ViewIdentities] = true
	model.setView(indexOfView(ViewIdentities))
	frame := ansi.Strip(model.View())
	if strings.Contains(frame, "identity-4999") || !strings.Contains(frame, "identity-0000") {
		t.Fatalf("list was not windowed:\n%s", frame)
	}
	if lines := strings.Count(frame, "identity-"); lines > model.pageSize()+1 {
		t.Fatalf("rendered %d list rows, page size %d", lines, model.pageSize())
	}
}

func TestResponsiveAccessChainLayoutsAtRepresentativeSizes(t *testing.T) {
	tests := []struct {
		width, height int
		prepare       func(*Model)
		want          []string
		absent        []string
	}{
		{width: 70, height: 24, prepare: func(model *Model) { model.focus, model.compactDetail = panelAccess, true }, want: []string{"Access Chain · Esc back", "BOUND_BY", "ANALYSIS"}, absent: []string{"Evidence"}},
		{width: 100, height: 30, prepare: func(model *Model) { model.focus = panelAccess }, want: []string{"Findings", "Access Chain", "BOUND_BY", "ANALYSIS"}, absent: []string{"Evidence"}},
		{width: 130, height: 34, want: []string{"Findings", "Inspector", "Access Chain", "BOUND_BY", "ANALYSIS"}, absent: []string{"Evidence"}},
		{width: 170, height: 36, want: []string{"Findings", "Inspector", "Access Chain", "Evidence", "BOUND_BY", "ANALYSIS"}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%dx%d", test.width, test.height), func(t *testing.T) {
			model := readyTestModel(t, test.width, test.height)
			model.setView(indexOfView(ViewFindings))
			if test.prepare != nil {
				test.prepare(model)
				model.syncViewports()
			}
			frame := ansi.Strip(model.View())
			for index, line := range strings.Split(frame, "\n") {
				if width := lipgloss.Width(line); width > test.width {
					t.Fatalf("line %d width = %d, terminal width = %d\n%s", index+1, width, test.width, line)
				}
			}
			for _, wanted := range test.want {
				if !strings.Contains(frame, wanted) {
					t.Fatalf("frame lacks %q:\n%s", wanted, frame)
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(frame, absent) {
					t.Fatalf("frame unexpectedly contains %q:\n%s", absent, frame)
				}
			}
			if second := ansi.Strip(model.View()); second != frame {
				t.Fatal("rendering the same state is not deterministic")
			}
		})
	}
}

func TestResizeKeepsAccessDetailVisibleWhenEvidenceColumnDisappears(t *testing.T) {
	model := readyTestModel(t, 170, 36)
	model.setView(indexOfView(ViewFindings))
	model.focus = panelEvidence
	_, _ = model.Update(tea.WindowSizeMsg{Width: 130, Height: 34})
	if model.focus != panelAccess || model.compactDetail {
		t.Fatalf("130-column focus = %d compact = %t, want Access Chain in multi-panel mode", model.focus, model.compactDetail)
	}
	_, _ = model.Update(tea.WindowSizeMsg{Width: 70, Height: 24})
	if model.focus != panelAccess || !model.compactDetail {
		t.Fatalf("70-column focus = %d compact = %t, want Access Chain in compact detail mode", model.focus, model.compactDetail)
	}
	if frame := ansi.Strip(model.View()); !strings.Contains(frame, "Access Chain · Esc back") {
		t.Fatalf("compact access chain is not visible:\n%s", frame)
	}
}

func TestPermissionGrantCountIsScopedToSelectedCapability(t *testing.T) {
	selected := permission.Capability{Verb: "delete", Resource: "secrets", Scope: permission.ScopeNamespaced, Namespace: "prod"}
	values := []explain.AccessExplanation{
		{Capabilities: []explain.CapabilitySummary{
			{Verb: "delete", Resource: "secrets", Scope: permission.ScopeNamespaced, Namespace: "prod", GrantIDs: []string{"grant-delete-a"}},
			{Verb: "get", Resource: "pods", Scope: permission.ScopeNamespaced, Namespace: "prod", GrantIDs: []string{"grant-pods-a"}},
		}},
		{Capabilities: []explain.CapabilitySummary{{Verb: "delete", Resource: "secrets", Scope: permission.ScopeNamespaced, Namespace: "prod", GrantIDs: []string{"grant-delete-b"}}}},
	}
	if got := explanationGrantCount(values, selected); got != 2 {
		t.Fatalf("grant count = %d, want 2", got)
	}
	evidence := explanationEvidence(values, selected)
	if strings.Contains(evidence, "grant-pods-a") || !strings.Contains(evidence, "grant-delete-a") || !strings.Contains(evidence, "grant-delete-b") {
		t.Fatalf("evidence was not scoped to delete secrets:\n%s", evidence)
	}
}

func TestRenderSnapshotUsesRealAnalysis(t *testing.T) {
	frame, err := RenderSnapshot(context.Background(), loadTestSnapshot(t), 100, 30, ViewFindings)
	if err != nil {
		t.Fatal(err)
	}
	plain := ansi.Strip(frame)
	if !strings.Contains(plain, "RBACVIZ") || !strings.Contains(plain, "RISK INDEX 77 HIGH") || !strings.Contains(plain, "ServiceAccount token") {
		t.Fatalf("unexpected release frame:\n%s", plain)
	}
}

func readyTestModel(t *testing.T, width, height int) *Model {
	t.Helper()
	model := NewModel(Options{Context: context.Background(), NoColor: true})
	t.Cleanup(model.Close)
	model.data = buildTestDataset(t)
	model.finishLoading()
	_, _ = model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return model
}

func buildTestDataset(t *testing.T) Dataset {
	t.Helper()
	ctx := context.Background()
	value := loadTestSnapshot(t)
	graphAnalyzer, err := app.NewGraphAnalyzer(value)
	if err != nil {
		t.Fatal(err)
	}
	findingsAnalyzer, err := app.NewFindingsAnalyzer(value)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := findingsAnalyzer.Analyze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	riskAnalyzer, err := app.NewRiskAnalyzer(value)
	if err != nil {
		t.Fatal(err)
	}
	risks, err := riskAnalyzer.Analyze(ctx, risk.Query{MaxPaths: 10000, MaxExpanded: 100000})
	if err != nil {
		t.Fatal(err)
	}
	nodes := graphAnalyzer.Select(graphmodel.Selector{})
	explanations, err := explain.Build(ctx, value, nodes, findings, attackpath.Result{}, risks)
	if err != nil {
		t.Fatal(err)
	}
	return Dataset{Snapshot: value, Graph: graphAnalyzer.Stats(), Nodes: nodes, Findings: findings, Risk: risks, Explanations: explanations}
}

func loadTestSnapshot(t *testing.T) snapshot.Snapshot {
	t.Helper()
	value, err := snapshot.Load(filepath.Join("..", "..", "examples", "risk-token-minter.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func BenchmarkRenderVirtualized5000Items(b *testing.B) {
	model := NewModel(Options{Context: context.Background(), NoColor: true})
	defer model.Close()
	model.loading, model.stage = false, stageReady
	model.data.Snapshot.Metadata.Complete = true
	model.data.Findings.Complete = true
	model.data.Risk.Complete = true
	model.items = make(map[View][]item)
	model.visible, model.dirty = make(map[View][]item), make(map[View]bool)
	values := make([]item, 5000)
	for index := range values {
		values[index] = item{ID: fmt.Sprintf("id-%04d", index), Title: fmt.Sprintf("identity-%04d", index), Risk: index % 100}
	}
	model.items[ViewIdentities] = values
	model.dirty[ViewIdentities] = true
	model.setView(indexOfView(ViewIdentities))
	_, _ = model.Update(tea.WindowSizeMsg{Width: 120, Height: 35})
	b.ResetTimer()
	for range b.N {
		_ = model.View()
	}
}
