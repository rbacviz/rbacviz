package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	semanticdiff "github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func newDiffCommand(streams IOStreams, state *commandState) *cobra.Command {
	var maxPaths, maxExpanded int
	command := &cobra.Command{
		Use: "diff <before.json> <after.json>", Short: "Compare snapshots by effective security impact", Args: cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			options, err := diffOptions(maxPaths, maxExpanded)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.diff.options", err.Error(), err)
			}
			before, err := snapshot.Load(args[0])
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.diff.before", "cannot load before snapshot", err)
			}
			after, err := snapshot.Load(args[1])
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.diff.after", "cannot load after snapshot", err)
			}
			result, err := app.CompareSnapshots(command.Context(), before, after, options)
			if err != nil {
				return apperr.New(apperr.KindOperational, "cli.diff.analyze", "semantic snapshot diff failed", err)
			}
			return writeDiff(streams.Out, state.result.Config.Output, result)
		},
	}
	command.Flags().IntVar(&maxPaths, "max-paths", 10000, "maximum attack paths compared per snapshot")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 100000, "maximum attack template candidates expanded per snapshot")
	return command
}

func diffOptions(maxPaths, maxExpanded int) (semanticdiff.Options, error) {
	if maxPaths < 1 || maxPaths > 100000 {
		return semanticdiff.Options{}, fmt.Errorf("--max-paths must be between 1 and 100000")
	}
	if maxExpanded < 1 {
		return semanticdiff.Options{}, fmt.Errorf("--max-expanded must be at least 1")
	}
	return semanticdiff.Options{MaxPaths: maxPaths, MaxExpanded: maxExpanded}, nil
}

func writeDiff(writer io.Writer, output string, result semanticdiff.Result) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return apperr.New(apperr.KindOperational, "cli.diff.output", "cannot write diff output", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer,
		"semantic snapshot diff\ncomplete: %t\ntruncated: %t\ncluster risk: %d -> %d (%+d) %s -> %s\nobjects: +%d -%d ~%d\nidentities: +%d -%d\npermissions: +%d -%d grants~%d\nnew dangerous capabilities: %d\nfindings: +%d -%d\nattack paths: +%d -%d states~%d\ncontrols changed: %d\n",
		result.Complete, result.Truncated, result.Risk.Cluster.Before, result.Risk.Cluster.After, result.Risk.Cluster.Delta,
		result.Risk.Cluster.BeforeSeverity, result.Risk.Cluster.AfterSeverity,
		result.Summary.ObjectsAdded, result.Summary.ObjectsRemoved, result.Summary.ObjectsModified,
		result.Summary.IdentitiesAdded, result.Summary.IdentitiesRemoved,
		result.Summary.PermissionsAdded, result.Summary.PermissionsRemoved, result.Summary.PermissionGrantsChanged,
		result.Summary.DangerousCapabilitiesNew, result.Summary.FindingsAdded, result.Summary.FindingsRemoved,
		result.Summary.AttackPathsAdded, result.Summary.AttackPathsRemoved, result.Summary.AttackPathStatesChanged,
		result.Summary.ControlsChanged); err != nil {
		return apperr.New(apperr.KindOperational, "cli.diff.output", "cannot write diff output", err)
	}
	for _, item := range result.DangerousCapabilities {
		if _, err := fmt.Fprintf(writer, "dangerous %s: %s %s %s\n", item.Direction, item.Category, item.Identity.String(), formatDiffCapability(item.Capability)); err != nil {
			return apperr.New(apperr.KindOperational, "cli.diff.output", "cannot write diff output", err)
		}
	}
	for _, item := range result.AttackPaths.Added {
		if _, err := fmt.Fprintf(writer, "attack path ADDED: %s %s -> %s confidence=%s blocked=%t\n", item.TemplateID, item.Source.String(), item.Target.Type, item.Confidence, item.Blocked); err != nil {
			return apperr.New(apperr.KindOperational, "cli.diff.output", "cannot write diff output", err)
		}
	}
	for _, item := range result.AttackPaths.Removed {
		if _, err := fmt.Fprintf(writer, "attack path REMOVED: %s %s -> %s confidence=%s blocked=%t\n", item.TemplateID, item.Source.String(), item.Target.Type, item.Confidence, item.Blocked); err != nil {
			return apperr.New(apperr.KindOperational, "cli.diff.output", "cannot write diff output", err)
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(writer, "warning [%s]: %s: %s\n", warning.Side, warning.Code, warning.Message); err != nil {
			return apperr.New(apperr.KindOperational, "cli.diff.output", "cannot write diff output", err)
		}
	}
	return nil
}

func formatDiffCapability(value semanticdiff.Capability) string {
	resource := value.Resource
	if value.Subresource != "" {
		resource += "/" + value.Subresource
	}
	if value.NonResourceURL != "" {
		resource = value.NonResourceURL
	}
	if value.APIGroup != "" {
		resource += "." + value.APIGroup
	}
	if value.Namespace != "" {
		resource += " namespace=" + value.Namespace
	}
	return value.Verb + " " + resource
}
