package tui

import (
	"context"
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// Run executes the model with injectable streams and optional alternate screen.
func Run(ctx context.Context, input io.Reader, output io.Writer, model *Model, altScreen bool) error {
	options := []tea.ProgramOption{tea.WithContext(ctx), tea.WithInput(input), tea.WithOutput(output)}
	if altScreen {
		options = append(options, tea.WithAltScreen())
	}
	program := tea.NewProgram(model, options...)
	_, err := program.Run()
	model.Close()
	return err
}
