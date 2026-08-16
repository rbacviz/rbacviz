package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/explain"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// Model owns presentation state only; security conclusions remain in app results.
type Model struct {
	ctx         context.Context
	cancel      context.CancelFunc
	load        SnapshotLoader
	keys        KeyMap
	styles      styles
	evaluatedAt time.Time

	stage              stage
	loading            bool
	err                error
	pathsLoading       bool
	pathsCancel        context.CancelFunc
	pathsError         error
	remediationLoading bool
	remediationCancel  context.CancelFunc
	remediationError   error
	data               Dataset
	items              map[View][]item
	visible            map[View][]item
	dirty              map[View]bool

	width, height int
	viewIndex     int
	cursor        map[View]int
	offset        map[View]int
	search        map[View]string
	filter        map[View]int
	sort          map[View]int
	focus         panel
	modal         modal
	compactDetail bool
	status        string

	spinner   spinner.Model
	searchBox textinput.Model
	inspector viewport.Model
	access    viewport.Model
	evidence  viewport.Model
}

// NewModel creates one isolated, cancellable TUI model.
func NewModel(options Options) *Model {
	parent := options.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	keys := options.KeyMap
	if len(keys.Quit.Keys()) == 0 {
		keys = DefaultKeyMap()
	}
	spin := spinner.New()
	spin.Spinner = spinner.Dot
	input := textinput.New()
	input.Prompt = "/ "
	input.Placeholder = "filter current view"
	input.CharLimit = 160
	input.Width = 48
	return &Model{
		ctx: ctx, cancel: cancel, load: options.Load, keys: keys,
		styles: newStyles(options.NoColor), stage: stageSnapshot, loading: true,
		data: Dataset{Baseline: options.Baseline}, evaluatedAt: options.EvaluatedAt,
		items: make(map[View][]item), visible: make(map[View][]item), dirty: make(map[View]bool), cursor: make(map[View]int),
		offset: make(map[View]int), search: make(map[View]string),
		filter: make(map[View]int), sort: make(map[View]int),
		spinner: spin, searchBox: input,
		inspector: viewport.New(1, 1), access: viewport.New(1, 1), evidence: viewport.New(1, 1),
	}
}

// RenderSnapshot runs the same application analyzers as the interactive TUI
// and returns one deterministic no-color frame. Release screenshots use this
// path so documentation cannot drift into a hand-written mockup.
func RenderSnapshot(ctx context.Context, value snapshot.Snapshot, width, height int, view View) (string, error) {
	graphAnalyzer, err := app.NewGraphAnalyzer(value)
	if err != nil {
		return "", err
	}
	findingsAnalyzer, err := app.NewFindingsAnalyzer(value)
	if err != nil {
		return "", err
	}
	findings, err := findingsAnalyzer.Analyze(ctx)
	if err != nil {
		return "", err
	}
	riskAnalyzer, err := app.NewRiskAnalyzer(value)
	if err != nil {
		return "", err
	}
	risks, err := riskAnalyzer.Analyze(ctx, risk.Query{MaxPaths: 10000, MaxExpanded: 100000})
	if err != nil {
		return "", err
	}
	model := NewModel(Options{Context: ctx, NoColor: true})
	defer model.Close()
	nodes := graphAnalyzer.Select(graphmodel.Selector{})
	explanations, err := explain.Build(ctx, value, nodes, findings, attackpath.Result{}, risks)
	if err != nil {
		return "", err
	}
	model.data = Dataset{Snapshot: value, Graph: graphAnalyzer.Stats(), Nodes: nodes, Findings: findings, Risk: risks, ActiveRisk: risks, Explanations: explanations}
	model.finishLoading()
	_, _ = model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	for index, candidate := range views {
		if candidate == view {
			model.setView(index)
			return model.View(), nil
		}
	}
	return "", fmt.Errorf("unknown TUI view %d", view)
}

// Init starts snapshot acquisition and a non-blocking progress spinner.
func (model *Model) Init() tea.Cmd {
	return tea.Batch(model.spinner.Tick, loadSnapshotCmd(model.ctx, model.load))
}

// Close releases any in-flight analysis.
func (model *Model) Close() { model.cancel() }

// Dataset returns the immutable result bundle after loading.
func (model *Model) Dataset() Dataset { return model.data }

// CurrentView exposes the selected screen for deterministic tests and embedding.
func (model *Model) CurrentView() View { return views[model.viewIndex] }

func (model *Model) activeItems() []item {
	view := model.CurrentView()
	values, cached := model.visible[view]
	if model.dirty[view] || !cached {
		values = filterAndSort(model.items[view], view, model.search[view], model.filter[view], model.sort[view])
		model.visible[view], model.dirty[view] = values, false
	}
	if len(values) == 0 {
		model.cursor[view], model.offset[view] = 0, 0
		return values
	}
	if model.cursor[view] >= len(values) {
		model.cursor[view] = len(values) - 1
	}
	return values
}

func (model *Model) selected() (item, bool) {
	values := model.activeItems()
	if len(values) == 0 {
		return item{}, false
	}
	return values[model.cursor[model.CurrentView()]], true
}

func (model *Model) advance(next stage, command tea.Cmd) tea.Cmd {
	model.stage = next
	model.status = next.String()
	return command
}

func (model *Model) finishLoading() {
	model.stage, model.loading = stageReady, false
	model.items = buildItems(model.data)
	model.visible = make(map[View][]item, len(views))
	model.dirty = make(map[View]bool, len(views))
	for _, view := range views {
		model.dirty[view] = true
	}
	model.status = "analysis ready"
	model.resize()
}

func (model *Model) ensurePaths() tea.Cmd {
	if model.pathsLoading || model.data.Paths.SchemaVersion != "" {
		return nil
	}
	ctx, cancel := context.WithCancel(model.ctx)
	model.pathsLoading, model.pathsCancel, model.pathsError = true, cancel, nil
	model.status = stagePaths.String()
	return tea.Batch(model.spinner.Tick, loadPathsCmd(ctx, model.data))
}

func (model *Model) ensureRemediation() tea.Cmd {
	if model.remediationLoading || model.data.Remediation.SchemaVersion != "" {
		return nil
	}
	ctx, cancel := context.WithCancel(model.ctx)
	model.remediationLoading, model.remediationCancel, model.remediationError = true, cancel, nil
	model.status = "evaluating remediation candidates"
	return tea.Batch(model.spinner.Tick, loadRemediationCmd(ctx, model.data))
}

func (model *Model) fail(err error) {
	model.loading = false
	model.err = err
	if errors.Is(err, context.Canceled) {
		model.status = "analysis cancelled"
		return
	}
	model.status = "analysis failed"
}

func (model *Model) resize() {
	if model.width < 160 && model.focus == panelEvidence {
		model.focus = panelAccess
	}
	if model.width < 80 {
		model.compactDetail = model.focus != panelList
	} else {
		model.compactDetail = false
	}
	contentHeight := maxInt(3, model.height-7)
	model.inspector.Width = maxInt(12, inspectorWidth(model.width)-4)
	model.inspector.Height = contentHeight - 2
	model.access.Width = maxInt(12, accessWidth(model.width)-4)
	model.access.Height = contentHeight - 2
	model.evidence.Width = maxInt(12, evidenceWidth(model.width)-4)
	model.evidence.Height = contentHeight - 2
	model.searchBox.Width = maxInt(12, minInt(60, model.width-10))
	model.syncViewports()
}

func (model *Model) syncViewports() {
	selected, ok := model.selected()
	if !ok {
		model.inspector.SetContent("No matching items.")
		model.access.SetContent("No access chain available.")
		model.evidence.SetContent("No evidence available.")
		return
	}
	model.inspector.SetContent(wrapText(selected.Detail, maxInt(12, model.inspector.Width)))
	model.access.SetContent(wrapText(accessContent(model.data.Explanations.Lookup(selected.ID)), maxInt(12, model.access.Width)))
	evidence := selected.Evidence
	if strings.TrimSpace(evidence) == "" {
		evidence = "No additional evidence for this item."
	}
	model.evidence.SetContent(wrapText(evidence, maxInt(12, model.evidence.Width)))
	model.inspector.GotoTop()
	model.access.GotoTop()
	model.evidence.GotoTop()
}

func (model *Model) setView(index int) {
	if index < 0 {
		index = len(views) - 1
	}
	if index >= len(views) {
		index = 0
	}
	model.viewIndex = index
	model.focus, model.compactDetail = panelList, false
	model.status = fmt.Sprintf("view: %s", model.CurrentView())
	model.syncViewports()
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
