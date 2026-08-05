package tui

import "github.com/charmbracelet/lipgloss"

type styles struct {
	title, subtitle, dim, selected            lipgloss.Style
	tab, activeTab, panel, focused            lipgloss.Style
	banner, critical, high, medium, low, info lipgloss.Style
}

func newStyles(noColor bool) styles {
	base := styles{
		title: lipgloss.NewStyle().Bold(true), subtitle: lipgloss.NewStyle(), dim: lipgloss.NewStyle(),
		selected: lipgloss.NewStyle().Bold(true), tab: lipgloss.NewStyle().Padding(0, 1),
		activeTab: lipgloss.NewStyle().Bold(true).Padding(0, 1),
		panel:     lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		focused:   lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		banner:    lipgloss.NewStyle().Bold(true).Padding(0, 1),
		critical:  lipgloss.NewStyle().Bold(true), high: lipgloss.NewStyle().Bold(true), medium: lipgloss.NewStyle(), low: lipgloss.NewStyle(), info: lipgloss.NewStyle(),
	}
	if noColor {
		return base
	}
	base.title = base.title.Foreground(lipgloss.Color("#EDEDED"))
	base.subtitle = base.subtitle.Foreground(lipgloss.Color("#9AA4B2"))
	base.dim = base.dim.Foreground(lipgloss.Color("#6B7280"))
	base.selected = base.selected.Foreground(lipgloss.Color("#12151A")).Background(lipgloss.Color("#67E8F9"))
	base.tab = base.tab.Foreground(lipgloss.Color("#94A3B8"))
	base.activeTab = base.activeTab.Foreground(lipgloss.Color("#12151A")).Background(lipgloss.Color("#A78BFA"))
	base.panel = base.panel.BorderForeground(lipgloss.Color("#334155"))
	base.focused = base.focused.BorderForeground(lipgloss.Color("#67E8F9"))
	base.banner = base.banner.Foreground(lipgloss.Color("#1C1917")).Background(lipgloss.Color("#FBBF24"))
	base.critical = base.critical.Foreground(lipgloss.Color("#FB7185"))
	base.high = base.high.Foreground(lipgloss.Color("#F97316"))
	base.medium = base.medium.Foreground(lipgloss.Color("#FBBF24"))
	base.low = base.low.Foreground(lipgloss.Color("#60A5FA"))
	base.info = base.info.Foreground(lipgloss.Color("#94A3B8"))
	return base
}

func (value styles) severity(level, text string) string {
	switch level {
	case "CRITICAL":
		return value.critical.Render(text)
	case "HIGH":
		return value.high.Render(text)
	case "MEDIUM":
		return value.medium.Render(text)
	case "LOW":
		return value.low.Render(text)
	default:
		return value.info.Render(text)
	}
}
