package tui

import (
	"context"
	"errors"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/risk"
)

// Update handles input and asynchronous analysis progress.
func (model *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch value := message.(type) {
	case tea.WindowSizeMsg:
		model.width, model.height = value.Width, value.Height
		model.resize()
		return model, nil
	case snapshotLoadedMsg:
		model.data.Snapshot = value.value
		return model, model.advance(stageGraph, loadGraphCmd(model.ctx, model.data))
	case graphLoadedMsg:
		model.data.Graph, model.data.Nodes = value.stats, value.nodes
		return model, model.advance(stageFindings, loadFindingsCmd(model.ctx, model.data))
	case findingsLoadedMsg:
		model.data.Findings = value.value
		return model, model.advance(stageRisk, loadRiskCmd(model.ctx, model.data))
	case pathsLoadedMsg:
		model.data.Paths, model.data.Explanations = value.value, value.explanations
		model.pathsLoading, model.pathsCancel = false, nil
		model.items[ViewAttackPaths] = pathItems(model.data)
		model.items[ViewWarnings] = warningItems(model.data)
		model.dirty[ViewAttackPaths], model.dirty[ViewWarnings] = true, true
		model.status = "detailed attack paths ready"
		model.syncViewports()
		return model, nil
	case pathLoadErrorMsg:
		model.pathsLoading, model.pathsCancel, model.pathsError = false, nil, value.err
		if errors.Is(value.err, context.Canceled) {
			model.status = "attack-path analysis cancelled"
		} else {
			model.status = "attack-path analysis failed"
		}
		return model, nil
	case riskLoadedMsg:
		model.data.Risk = value.value
		model.data.ActiveRisk = value.value
		if model.data.Baseline != nil {
			evaluatedAt := model.evaluatedAt
			if evaluatedAt.IsZero() {
				evaluatedAt = time.Now()
			}
			model.data.Suppressions = baseline.Evaluate(*model.data.Baseline, model.data.Findings, value.value, evaluatedAt)
			model.data.ActiveRisk = risk.WithoutFamilies(value.value, model.data.Suppressions.AcceptedRiskFamilyIDs())
		}
		return model, model.advance(stageExplanations, loadExplanationsCmd(model.ctx, model.data))
	case explanationsLoadedMsg:
		model.data.Explanations = value.value
		model.finishLoading()
		return model, nil
	case remediationLoadedMsg:
		model.data.Remediation, model.remediationLoading, model.remediationCancel = value.value, false, nil
		model.status = "remediation candidates ready"
		return model, nil
	case remediationLoadErrorMsg:
		model.remediationLoading, model.remediationCancel, model.remediationError = false, nil, value.err
		if errors.Is(value.err, context.Canceled) {
			model.status = "remediation analysis cancelled"
		} else {
			model.status = "remediation analysis failed"
		}
		return model, nil
	case loadErrorMsg:
		model.fail(value.err)
		return model, nil
	case spinner.TickMsg:
		var command tea.Cmd
		model.spinner, command = model.spinner.Update(value)
		if model.loading || model.pathsLoading || model.remediationLoading {
			return model, command
		}
		return model, nil
	case tea.KeyMsg:
		return model.handleKey(value)
	}
	return model.updateViewport(message)
}

func (model *Model) handleKey(message tea.KeyMsg) (tea.Model, tea.Cmd) {
	if model.modal == modalSearch {
		return model.handleSearchKey(message)
	}
	if model.modal != modalNone {
		if key.Matches(message, model.keys.Back, model.keys.Quit) {
			if model.modal == modalRemediation && model.remediationLoading && model.remediationCancel != nil {
				model.remediationCancel()
			}
			model.modal = modalNone
			model.status = "modal closed"
			return model, nil
		}
		return model.updateViewport(message)
	}
	if model.loading {
		if key.Matches(message, model.keys.Back, model.keys.Cancel, model.keys.Quit) {
			model.cancel()
			model.status = "cancelling analysis"
		}
		return model, nil
	}
	if model.pathsLoading && key.Matches(message, model.keys.Back) {
		if model.pathsCancel != nil {
			model.pathsCancel()
		}
		model.status = "cancelling attack-path analysis"
		return model, nil
	}
	if key.Matches(message, model.keys.Cancel, model.keys.Quit) {
		model.cancel()
		return model, tea.Quit
	}
	if model.err != nil {
		return model, nil
	}

	switch {
	case key.Matches(message, model.keys.Help):
		model.modal = modalHelp
	case key.Matches(message, model.keys.Search):
		model.modal = modalSearch
		model.searchBox.SetValue(model.search[model.CurrentView()])
		model.searchBox.CursorEnd()
		return model, model.searchBox.Focus()
	case key.Matches(message, model.keys.Filter):
		view := model.CurrentView()
		model.filter[view] = (model.filter[view] + 1) % filterCount(view)
		model.dirty[view] = true
		model.cursor[view], model.offset[view] = 0, 0
		model.status = "filter: " + filterLabel(view, model.filter[view])
		model.syncViewports()
	case key.Matches(message, model.keys.Sort):
		view := model.CurrentView()
		model.sort[view] = (model.sort[view] + 1) % sortCount(view)
		model.dirty[view] = true
		model.cursor[view], model.offset[view] = 0, 0
		model.status = "sort: " + sortLabel(view, model.sort[view])
		model.syncViewports()
	case key.Matches(message, model.keys.NextView):
		model.setView(model.viewIndex + 1)
		if model.CurrentView() == ViewAttackPaths {
			return model, model.ensurePaths()
		}
	case key.Matches(message, model.keys.PreviousView):
		model.setView(model.viewIndex - 1)
		if model.CurrentView() == ViewAttackPaths {
			return model, model.ensurePaths()
		}
	case key.Matches(message, model.keys.NextPanel):
		model.movePanel(1)
	case key.Matches(message, model.keys.PreviousPanel):
		model.movePanel(-1)
	case key.Matches(message, model.keys.Inspect):
		if model.width < 80 {
			model.compactDetail = true
			model.focus = panelInspector
		} else {
			model.focus = panelInspector
		}
	case key.Matches(message, model.keys.Back):
		model.back()
	case key.Matches(message, model.keys.Evidence):
		model.modal = modalEvidence
		model.evidence.GotoTop()
	case key.Matches(message, model.keys.Remediation):
		model.modal = modalRemediation
		return model, model.ensureRemediation()
	case key.Matches(message, model.keys.Paths):
		return model, model.openPaths()
	case key.Matches(message, model.keys.Up):
		model.moveSelection(-1)
	case key.Matches(message, model.keys.Down):
		model.moveSelection(1)
	case key.Matches(message, model.keys.PageUp):
		model.moveSelection(-model.pageSize())
	case key.Matches(message, model.keys.PageDown):
		model.moveSelection(model.pageSize())
	case key.Matches(message, model.keys.Home):
		model.moveSelection(-1 << 20)
	case key.Matches(message, model.keys.End):
		model.moveSelection(1 << 20)
	}
	return model, nil
}

func (model *Model) handleSearchKey(message tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.Matches(message, model.keys.Back) {
		model.modal = modalNone
		model.searchBox.Blur()
		return model, nil
	}
	if message.Type == tea.KeyEnter {
		view := model.CurrentView()
		model.search[view] = model.searchBox.Value()
		model.dirty[view] = true
		model.cursor[view], model.offset[view] = 0, 0
		model.modal = modalNone
		model.searchBox.Blur()
		model.status = "search applied"
		model.syncViewports()
		return model, nil
	}
	var command tea.Cmd
	model.searchBox, command = model.searchBox.Update(message)
	return model, command
}

func (model *Model) moveSelection(delta int) {
	if model.focus != panelList && model.width >= 80 {
		switch model.focus {
		case panelInspector:
			if delta < 0 {
				model.inspector.ScrollUp(1)
			} else {
				model.inspector.ScrollDown(1)
			}
		case panelAccess:
			if delta < 0 {
				model.access.ScrollUp(1)
			} else {
				model.access.ScrollDown(1)
			}
		case panelEvidence:
			if delta < 0 {
				model.evidence.ScrollUp(1)
			} else {
				model.evidence.ScrollDown(1)
			}
		}
		return
	}
	view := model.CurrentView()
	values := model.activeItems()
	if len(values) == 0 {
		return
	}
	model.cursor[view] += delta
	if model.cursor[view] < 0 {
		model.cursor[view] = 0
	}
	if model.cursor[view] >= len(values) {
		model.cursor[view] = len(values) - 1
	}
	model.keepVisible(len(values))
	model.syncViewports()
}

func (model *Model) keepVisible(total int) {
	view, size := model.CurrentView(), model.pageSize()
	if model.cursor[view] < model.offset[view] {
		model.offset[view] = model.cursor[view]
	}
	if model.cursor[view] >= model.offset[view]+size {
		model.offset[view] = model.cursor[view] - size + 1
	}
	maximum := maxInt(0, total-size)
	if model.offset[view] > maximum {
		model.offset[view] = maximum
	}
}

func (model *Model) pageSize() int { return maxInt(3, model.height-10) }

func (model *Model) movePanel(delta int) {
	count := 1
	if model.width < 80 && model.compactDetail {
		count = 3
	} else if model.width >= 80 {
		count = 3
	}
	if model.width >= 160 {
		count = 4
	}
	model.focus = panel((int(model.focus) + delta + count) % count)
	if model.width < 80 {
		model.compactDetail = model.focus != panelList
	}
	model.status = []string{"list panel", "inspector panel", "access chain panel", "evidence panel"}[model.focus]
}

func (model *Model) back() {
	if model.compactDetail {
		model.compactDetail = false
		model.focus = panelList
		return
	}
	if model.focus != panelList {
		model.focus = panelList
		return
	}
	view := model.CurrentView()
	if model.search[view] != "" {
		model.search[view] = ""
		model.dirty[view] = true
		model.cursor[view], model.offset[view] = 0, 0
		model.syncViewports()
	}
}

func (model *Model) openPaths() tea.Cmd {
	selected, ok := model.selected()
	model.setView(indexOfView(ViewAttackPaths))
	if ok && selected.ID != "" {
		model.search[ViewAttackPaths] = selected.Title
		model.dirty[ViewAttackPaths] = true
		if len(model.activeItems()) == 0 {
			model.search[ViewAttackPaths] = ""
			model.dirty[ViewAttackPaths] = true
		}
	}
	return model.ensurePaths()
}

func (model *Model) updateViewport(message tea.Msg) (tea.Model, tea.Cmd) {
	var command tea.Cmd
	switch {
	case model.modal == modalEvidence || model.focus == panelEvidence:
		model.evidence, command = model.evidence.Update(message)
	case model.focus == panelAccess:
		model.access, command = model.access.Update(message)
	default:
		model.inspector, command = model.inspector.Update(message)
	}
	return model, command
}

func indexOfView(wanted View) int {
	for index, value := range views {
		if value == wanted {
			return index
		}
	}
	return 0
}
