package tui

import (
	"context"
	"crypto/sha256"
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
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

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
	if len(model.data.Findings.Findings) == 0 || len(model.data.Risk.PathScores) == 0 || model.data.Graph.Nodes == 0 {
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

func TestGoldenFramesAtRepresentativeSizes(t *testing.T) {
	tests := []struct {
		width, height int
		want          string
	}{
		{width: 72, height: 24, want: "0c49d058519adbae4457924c5ad732764559a3085104d5380155c0b072604066"},
		{width: 100, height: 30, want: "5a5f91b251be463723cb400f41537d198a0d9c70e63634612e39b0d5936f6dc8"},
		{width: 140, height: 34, want: "b55bfaca6caf72be24bf8385453d7038464b39843475b6d2596f95c425d0d94b"},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%dx%d", test.width, test.height), func(t *testing.T) {
			model := readyTestModel(t, test.width, test.height)
			frame := ansi.Strip(model.View())
			for index, line := range strings.Split(frame, "\n") {
				if width := lipgloss.Width(line); width > test.width {
					t.Fatalf("line %d width = %d, terminal width = %d\n%s", index+1, width, test.width, line)
				}
			}
			got := fmt.Sprintf("%x", sha256.Sum256([]byte(frame)))
			if got != test.want {
				t.Fatalf("render digest = %s, want %s\n--- frame ---\n%s", got, test.want, frame)
			}
		})
	}
}

func TestRenderSnapshotUsesRealAnalysis(t *testing.T) {
	frame, err := RenderSnapshot(context.Background(), loadTestSnapshot(t), 100, 30, ViewFindings)
	if err != nil {
		t.Fatal(err)
	}
	plain := ansi.Strip(frame)
	if !strings.Contains(plain, "RBACVIZ") || !strings.Contains(plain, "RISK 77 HIGH") || !strings.Contains(plain, "ServiceAccount token") {
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
	return Dataset{Snapshot: value, Graph: graphAnalyzer.Stats(), Nodes: graphAnalyzer.Select(graphmodel.Selector{}), Findings: findings, Risk: risks}
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
