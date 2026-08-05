package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/snapshot"
	tuiterm "github.com/rbacviz/rbacviz/internal/tui"
)

func newTUICommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var noAltScreen bool
	command := &cobra.Command{
		Use:   "tui",
		Short: "Explore cluster identities, findings, attack paths, and risk interactively",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if state.result.Config.Output != "human" {
				return apperr.New(apperr.KindInvalidInput, "cli.tui.output", "tui requires --output human", nil)
			}
			model := tuiterm.NewModel(tuiterm.Options{
				Context: command.Context(), NoColor: state.result.Config.NoColor,
				Load: func(ctx context.Context) (snapshot.Snapshot, error) {
					return loadAnalysisSnapshot(ctx, dependencies, state)
				},
			})
			if err := tuiterm.Run(command.Context(), streams.In, streams.Out, model, !noAltScreen); err != nil {
				return apperr.New(apperr.KindOperational, "cli.tui.run", fmt.Sprintf("terminal UI stopped: %v", err), err)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&noAltScreen, "no-alt-screen", false, "render inline instead of using the terminal alternate screen")
	return command
}
