package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap is the single configurable source of keyboard bindings.
type KeyMap struct {
	Up, Down, Inspect, Back      key.Binding
	Search, Filter, Sort         key.Binding
	NextPanel, PreviousPanel     key.Binding
	NextView, PreviousView       key.Binding
	Evidence, Paths, Remediation key.Binding
	Help, Quit, Cancel, PageUp   key.Binding
	PageDown, Home, End          key.Binding
}

// DefaultKeyMap returns the keyboard-first navigation contract.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up:            binding([]string{"up", "k"}, "↑/k", "up"),
		Down:          binding([]string{"down", "j"}, "↓/j", "down"),
		Inspect:       binding([]string{"enter"}, "enter", "inspect"),
		Back:          binding([]string{"esc"}, "esc", "back"),
		Search:        binding([]string{"/"}, "/", "search"),
		Filter:        binding([]string{"f"}, "f", "filter"),
		Sort:          binding([]string{"s"}, "s", "sort"),
		NextPanel:     binding([]string{"tab"}, "tab", "next panel"),
		PreviousPanel: binding([]string{"shift+tab"}, "shift+tab", "previous panel"),
		NextView:      binding([]string{"right", "]", "l"}, "→/l", "next view"),
		PreviousView:  binding([]string{"left", "[", "h"}, "←/h", "previous view"),
		Evidence:      binding([]string{"e"}, "e", "evidence"),
		Paths:         binding([]string{"p"}, "p", "paths"),
		Remediation:   binding([]string{"r"}, "r", "remediation"),
		Help:          binding([]string{"?"}, "?", "help"),
		Quit:          binding([]string{"q"}, "q", "quit"),
		Cancel:        binding([]string{"ctrl+c"}, "ctrl+c", "cancel"),
		PageUp:        binding([]string{"pgup", "ctrl+u"}, "pgup", "page up"),
		PageDown:      binding([]string{"pgdown", "ctrl+d"}, "pgdn", "page down"),
		Home:          binding([]string{"home", "g"}, "g", "first"),
		End:           binding([]string{"end", "G"}, "G", "last"),
	}
}

func binding(keys []string, helpKey, description string) key.Binding {
	return key.NewBinding(key.WithKeys(keys...), key.WithHelp(helpKey, description))
}
