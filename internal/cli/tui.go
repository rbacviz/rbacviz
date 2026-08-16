package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/snapshot"
	tuiterm "github.com/rbacviz/rbacviz/internal/tui"
)

func newTUICommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var noAltScreen bool
	var baselinePath string
	command := &cobra.Command{
		Use:   "tui",
		Short: "Explore cluster identities, findings, attack paths, and risk interactively",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if state.result.Config.Output != "human" {
				return apperr.New(apperr.KindInvalidInput, "cli.tui.output", "tui requires --output human", nil)
			}
			var policy *baseline.Document
			if strings.TrimSpace(baselinePath) != "" {
				loaded, err := baseline.Load(baselinePath)
				if err != nil {
					return apperr.New(apperr.KindInvalidInput, "cli.tui.baseline", err.Error(), err)
				}
				policy = &loaded
			}
			model := tuiterm.NewModel(tuiterm.Options{
				Context: command.Context(), NoColor: state.result.Config.NoColor,
				Baseline: policy, EvaluatedAt: time.Now().UTC(),
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
	command.Flags().StringVar(&baselinePath, "baseline", "", "path to a reviewed YAML or JSON suppression baseline")
	return command
}
