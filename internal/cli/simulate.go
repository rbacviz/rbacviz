package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/simulate"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func newSimulateCommand(streams IOStreams, state *commandState) *cobra.Command {
	var files []string
	var maxPaths, maxExpanded int
	command := &cobra.Command{
		Use: "simulate -s <snapshot.json> -f <manifest-or-directory>", Short: "Measure proposed manifest impact without contacting a cluster", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if state.result.Config.Snapshot == "" {
				return apperr.New(apperr.KindInvalidInput, "cli.simulate.snapshot", "simulate requires --snapshot/-s and never falls back to a live cluster", nil)
			}
			if len(files) == 0 {
				return apperr.New(apperr.KindInvalidInput, "cli.simulate.files", "at least one --file/-f is required", nil)
			}
			diffOptions, err := diffOptions(maxPaths, maxExpanded)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.simulate.options", err.Error(), err)
			}
			base, err := snapshot.Load(state.result.Config.Snapshot)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.simulate.snapshot", "cannot load simulation snapshot", err)
			}
			defaultNamespace := state.result.Config.Namespace
			if defaultNamespace == "" {
				defaultNamespace = base.Metadata.Namespace
			}
			manifests := []simulate.Manifest{}
			for _, path := range files {
				loaded, err := simulate.LoadPath(path, defaultNamespace)
				if err != nil {
					return apperr.New(apperr.KindInvalidInput, "cli.simulate.manifest", err.Error(), err)
				}
				manifests = append(manifests, loaded...)
			}
			result, err := app.SimulateManifests(command.Context(), base, manifests, simulate.Options{DefaultNamespace: defaultNamespace, Diff: diffOptions})
			if err != nil {
				return apperr.New(apperr.KindOperational, "cli.simulate.run", "offline simulation failed", err)
			}
			return writeSimulation(streams.Out, state.result.Config.Output, result)
		},
	}
	command.Flags().StringArrayVarP(&files, "file", "f", nil, "manifest file or directory; may be repeated")
	command.Flags().IntVar(&maxPaths, "max-paths", 10000, "maximum attack paths compared per snapshot")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 100000, "maximum attack template candidates expanded per snapshot")
	return command
}

func writeSimulation(writer io.Writer, output string, result simulate.Result) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return apperr.New(apperr.KindOperational, "cli.simulate.output", "cannot write simulation output", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer, "offline simulation\napplied manifests: %d\n", len(result.Applied)); err != nil {
		return apperr.New(apperr.KindOperational, "cli.simulate.output", "cannot write simulation output", err)
	}
	for _, item := range result.Applied {
		if _, err := fmt.Fprintf(writer, "applied: %s %s %s/%s existed=%t source=%s#%d\n", item.Operation, item.Ref.Kind, item.Ref.Namespace, item.Ref.Name, item.Existed, item.Source, item.Document); err != nil {
			return apperr.New(apperr.KindOperational, "cli.simulate.output", "cannot write simulation output", err)
		}
	}
	return writeDiff(writer, "human", result.Diff)
}
