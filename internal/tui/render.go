package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// View renders a responsive terminal frame.
func (model *Model) View() string {
	width, height := model.width, model.height
	if width < 1 {
		width = 100
	}
	if height < 1 {
		height = 30
	}
	header := model.renderHeader(width)
	if model.loading {
		body := model.center(width, height-4, fmt.Sprintf("%s  %s\n\nEsc cancels safely", model.spinner.View(), model.stage.String()))
		return header + "\n" + body + "\n" + model.renderFooter(width)
	}
	if model.err != nil {
		body := model.center(width, height-4, "ANALYSIS STOPPED\n\n"+model.err.Error()+"\n\nPress q to quit")
		return header + "\n" + body + "\n" + model.renderFooter(width)
	}

	parts := []string{header, model.renderTabs(width)}
	if model.incomplete() {
		parts = append(parts, model.renderIncomplete(width))
	}
	if model.modal != modalNone {
		parts = append(parts, model.renderModal(width, height-len(parts)-2))
	} else {
		parts = append(parts, model.renderBody(width, height-len(parts)-2))
	}
	parts = append(parts, model.renderFooter(width))
	return strings.Join(parts, "\n")
}

func (model *Model) renderHeader(width int) string {
	left := model.styles.title.Render("RBACVIZ") + "  " + model.styles.subtitle.Render("Kubernetes identity attack surface")
	right := ""
	if !model.loading && model.err == nil {
		right = model.styles.severity(string(model.data.Risk.Cluster.Severity), fmt.Sprintf("RISK %d %s", model.data.Risk.Cluster.Score, model.data.Risk.Cluster.Severity))
	}
	space := maxInt(1, width-lipgloss.Width(left)-lipgloss.Width(right))
	return truncate(left+strings.Repeat(" ", space)+right, width)
}

func (model *Model) renderTabs(width int) string {
	if width < 100 {
		return model.styles.activeTab.Render(fmt.Sprintf("%d/%d  %s", model.viewIndex+1, len(views), model.CurrentView())) + model.styles.dim.Render("   ←/→ switch view")
	}
	labels := make([]string, 0, len(views))
	for index, view := range views {
		label := shortView(view)
		if index == model.viewIndex {
			labels = append(labels, model.styles.activeTab.Render(label))
		} else {
			labels = append(labels, model.styles.tab.Render(label))
		}
	}
	return truncate(strings.Join(labels, ""), width)
}

func shortView(view View) string {
	switch view {
	case ViewServiceAccounts:
		return "SAs"
	case ViewClusterRoles:
		return "CRoles"
	case ViewAttackPaths:
		return "Paths"
	default:
		return view.String()
	}
}

func (model *Model) renderIncomplete(width int) string {
	message := fmt.Sprintf("INCOMPLETE ANALYSIS · %d collection warnings · conclusions may not be exhaustive", len(model.data.Snapshot.Warnings))
	return model.styles.banner.Width(maxInt(1, width-2)).Render(truncate(message, maxInt(1, width-4)))
}

func (model *Model) renderBody(width, height int) string {
	height = maxInt(4, height)
	if width < 80 {
		if model.compactDetail {
			return model.renderCompactInspector(width, height)
		}
		return model.renderListPanel(width, height)
	}
	listWidth := width * 40 / 100
	if width >= 120 {
		listWidth = width * 31 / 100
	}
	remaining := width - listWidth - 1
	inspector := remaining
	if width >= 120 {
		inspector = width * 39 / 100
	}
	list := model.renderListPanel(listWidth, height)
	detail := model.renderInspectorPanel(inspector, height)
	if width < 120 {
		return lipgloss.JoinHorizontal(lipgloss.Top, list, " ", detail)
	}
	evidenceWidth := maxInt(20, width-listWidth-inspector-2)
	evidence := model.renderEvidencePanel(evidenceWidth, height)
	return lipgloss.JoinHorizontal(lipgloss.Top, list, " ", detail, " ", evidence)
}

func (model *Model) renderListPanel(width, height int) string {
	view := model.CurrentView()
	values := model.activeItems()
	page := maxInt(1, height-5)
	model.keepVisible(len(values))
	start := model.offset[view]
	end := minInt(len(values), start+page)
	rows := make([]string, 0, page+2)
	meta := fmt.Sprintf("%d items · filter %s · sort %s", len(values), filterLabel(view, model.filter[view]), sortLabel(view, model.sort[view]))
	if view == ViewAttackPaths && model.pathsLoading {
		meta = model.spinner.View() + " loading detailed paths · Esc cancel"
	} else if view == ViewAttackPaths && model.pathsError != nil {
		meta = "path detail error: " + model.pathsError.Error()
	}
	if model.search[view] != "" {
		meta += " · /" + model.search[view]
	}
	rows = append(rows, model.styles.dim.Render(truncate(meta, maxInt(1, width-6))))
	if len(values) == 0 {
		rows = append(rows, "", "No matching items.")
	}
	for index := start; index < end; index++ {
		value, marker := values[index], "  "
		line := value.Title
		if value.Severity != "" {
			line = "[" + value.Severity + "] " + line
		}
		if index == model.cursor[view] {
			marker = "› "
			rows = append(rows, model.styles.selected.Render(truncate(marker+line, maxInt(1, width-6))))
		} else {
			rows = append(rows, model.styles.severity(value.Severity, truncate(marker+line, maxInt(1, width-6))))
		}
	}
	rows = append(rows, model.styles.dim.Render(fmt.Sprintf("%d–%d of %d", minInt(start+1, len(values)), end, len(values))))
	return model.panel(width, height, model.focus == panelList, view.String(), strings.Join(rows, "\n"))
}

func (model *Model) renderInspectorPanel(width, height int) string {
	return model.panel(width, height, model.focus == panelInspector, "Inspector", model.inspector.View())
}

func (model *Model) renderEvidencePanel(width, height int) string {
	return model.panel(width, height, model.focus == panelEvidence, "Evidence", model.evidence.View())
}

func (model *Model) renderCompactInspector(width, height int) string {
	selected, ok := model.selected()
	body := "No matching item."
	if ok {
		body = wrapText(selected.Detail, maxInt(12, width-6))
	}
	return model.panel(width, height, true, "Inspector · Esc back", body)
}

func (model *Model) panel(width, height int, focused bool, title, body string) string {
	style := model.styles.panel
	if focused {
		style = model.styles.focused
	}
	contentWidth, contentHeight := maxInt(1, width-4), maxInt(1, height-2)
	content := model.styles.title.Render(title) + "\n" + body
	return style.Width(contentWidth).Height(contentHeight).MaxHeight(contentHeight).Render(content)
}

func (model *Model) renderModal(width, height int) string {
	modalWidth := minInt(84, maxInt(20, width-8))
	body, title := "", ""
	switch model.modal {
	case modalSearch:
		title, body = "Search", model.searchBox.View()+"\n\nEnter applies · Esc cancels"
	case modalHelp:
		title, body = "Keyboard help", helpText()
	case modalEvidence:
		title, body = "Evidence", model.evidence.View()
	case modalRemediation:
		title, body = "Simulated remediation", "No remediation candidate for this item."
		if model.remediationLoading {
			body = model.spinner.View() + " virtually applying and measuring candidates\n\nEsc cancels safely"
		} else if model.remediationError != nil {
			body = "Remediation analysis failed: " + model.remediationError.Error()
		} else if selected, ok := model.selected(); ok {
			body = remediationPanel(model.data, selected.ID)
		}
		body = wrapText(body, modalWidth-6)
	}
	box := model.styles.focused.Width(modalWidth - 4).Height(maxInt(4, minInt(height-2, 22))).Render(model.styles.title.Render(title) + "\n\n" + body + "\n\nEsc/q closes")
	return lipgloss.Place(width, maxInt(4, height), lipgloss.Center, lipgloss.Center, box)
}

func helpText() string {
	return strings.Join([]string{
		"↑/↓ or j/k      move / scroll focused panel", "←/→ or h/l      previous / next view",
		"Enter            inspect", "Esc              back / clear search", "/                search current view",
		"f                cycle filters", "s                cycle sort", "Tab / Shift+Tab  switch panels",
		"e                evidence", "p                attack paths", "r                advisory remediation",
		"PgUp/PgDn        page", "g/G              first / last", "q                quit", "Ctrl+C           cancel",
	}, "\n")
}

func (model *Model) renderFooter(width int) string {
	hints := "←/→ view  ↑/↓ move  enter inspect  / search  f filter  s sort  ? help  q quit"
	if model.loading {
		hints = "Esc cancel analysis"
	}
	status := model.status
	space := maxInt(1, width-len([]rune(status))-len([]rune(hints)))
	return truncate(model.styles.dim.Render(status+strings.Repeat(" ", space)+hints), width)
}

func (model *Model) center(width, height int, text string) string {
	return lipgloss.Place(width, maxInt(1, height), lipgloss.Center, lipgloss.Center, model.styles.title.Render(text))
}

func (model *Model) incomplete() bool {
	pathsIncomplete := model.data.Paths.SchemaVersion != "" && !model.data.Paths.Complete
	remediationIncomplete := model.data.Remediation.SchemaVersion != "" && !model.data.Remediation.Complete
	return !model.data.Snapshot.Metadata.Complete || !model.data.Findings.Complete || pathsIncomplete || !model.data.Risk.Complete || remediationIncomplete || len(model.data.Snapshot.Warnings) > 0
}

func inspectorWidth(width int) int {
	if width < 80 {
		return width
	}
	if width < 120 {
		return width - width*40/100 - 1
	}
	return width * 39 / 100
}

func evidenceWidth(width int) int {
	if width < 120 {
		return inspectorWidth(width)
	}
	return width - width*31/100 - width*39/100 - 2
}
