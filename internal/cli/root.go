// Package cli wires command-line input to application boundaries.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/config"
	"github.com/rbacviz/rbacviz/internal/logging"
	"github.com/rbacviz/rbacviz/internal/snapshot"
	"github.com/rbacviz/rbacviz/internal/version"
)

// IOStreams keeps command I/O injectable and deterministic.
type IOStreams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

// Dependencies are process services supplied by main and tests.
type Dependencies struct {
	Version         version.Info
	LookupEnv       func(string) (string, bool)
	UserConfigDir   func() (string, error)
	CollectSnapshot func(context.Context, config.Config, string) (snapshot.Snapshot, error)
}

type rawFlags struct {
	configPath    string
	context       string
	kubeconfig    string
	namespace     string
	allNamespaces bool
	snapshot      string
	output        string
	noColor       bool
	timeout       time.Duration
	logLevel      string
}

type commandState struct {
	result config.Result
	logger *slog.Logger
}

// Execute runs a complete CLI invocation and returns the documented process code.
func Execute(ctx context.Context, args []string, streams IOStreams, dependencies Dependencies) int {
	command := NewRootCommand(streams, dependencies)
	command.SetArgs(args)
	if err := command.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintf(streams.ErrOut, "error: %s\n", apperr.Message(err))
		if !apperr.IsTyped(err) {
			return 2 // Cobra parsing, unknown command, or argument validation.
		}
		return apperr.ExitCode(err)
	}
	return 0
}

// NewRootCommand builds a new command tree without mutable package globals.
func NewRootCommand(streams IOStreams, dependencies Dependencies) *cobra.Command {
	flags := rawFlags{output: config.DefaultOutput, timeout: config.DefaultTimeout, logLevel: config.DefaultLogLevel}
	state := &commandState{}

	root := &cobra.Command{
		Use:           "rbacviz",
		Short:         "Explore Kubernetes RBAC identity attack paths",
		Long:          "rbacviz is a terminal-first Kubernetes identity attack-path explorer.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
		PersistentPreRunE: func(command *cobra.Command, _ []string) error {
			result, err := loadConfig(command, flags, dependencies)
			if err != nil {
				return err
			}
			if result.Config.Output == "sarif" && command.Name() != "findings" && command.Name() != "explain" {
				return apperr.New(apperr.KindValidation, "cli.output", "SARIF output is supported by findings and explain", nil)
			}
			logger, err := logging.New(result.Config.LogLevel, streams.ErrOut)
			if err != nil {
				return apperr.New(apperr.KindValidation, "cli.logging", err.Error(), err)
			}
			state.result = result
			state.logger = logger
			command.SetContext(logging.WithContext(command.Context(), logger))
			return nil
		},
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.ErrOut)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return apperr.New(apperr.KindInvalidInput, "cli.flags", err.Error(), err)
	})
	root.CompletionOptions.DisableDefaultCmd = true
	root.DisableAutoGenTag = true

	persistent := root.PersistentFlags()
	persistent.StringVar(&flags.configPath, "config", "", "path to a JSON configuration file")
	persistent.StringVar(&flags.context, "context", "", "kubeconfig context to use")
	persistent.StringVar(&flags.kubeconfig, "kubeconfig", "", "path to a kubeconfig file")
	persistent.StringVarP(&flags.namespace, "namespace", "n", "", "limit namespaced analysis")
	persistent.BoolVarP(&flags.allNamespaces, "all-namespaces", "A", false, "analyze all namespaces")
	persistent.StringVarP(&flags.snapshot, "snapshot", "s", "", "analyze an offline snapshot instead of a live cluster")
	persistent.StringVar(&flags.output, "output", config.DefaultOutput, "output format: human, json, or sarif where supported")
	persistent.BoolVar(&flags.noColor, "no-color", false, "disable ANSI color output")
	persistent.DurationVar(&flags.timeout, "timeout", config.DefaultTimeout, "command timeout")
	persistent.StringVar(&flags.logLevel, "log-level", config.DefaultLogLevel, "log level: debug, info, warn, or error")

	root.AddCommand(newVersionCommand(streams, dependencies, state))
	root.AddCommand(newConfigCommand(streams, state))
	root.AddCommand(newSnapshotCommand(streams, dependencies, state))
	root.AddCommand(newPermissionsCommand(streams, dependencies, state))
	root.AddCommand(newWhoCanCommand(streams, dependencies, state))
	root.AddCommand(newWhyCanCommand(streams, dependencies, state))
	root.AddCommand(newGraphCommand(streams, dependencies, state))
	root.AddCommand(newFindingsCommand(streams, dependencies, state))
	root.AddCommand(newExplainCommand(streams, dependencies, state))
	root.AddCommand(newAttackPathCommand(streams, dependencies, state))
	root.AddCommand(newRiskCommand(streams, dependencies, state))
	root.AddCommand(newTUICommand(streams, dependencies, state))
	root.AddCommand(newDiffCommand(streams, state))
	root.AddCommand(newSimulateCommand(streams, state))
	root.AddCommand(newRemediateCommand(streams, dependencies, state))
	root.AddCommand(newReportCommand(streams, dependencies, state))
	return root
}

type snapshotSummary struct {
	SchemaVersion    string `json:"schemaVersion"`
	Complete         bool   `json:"complete"`
	APIResources     int    `json:"apiResources"`
	Identities       int    `json:"identities"`
	Roles            int    `json:"roles"`
	Bindings         int    `json:"bindings"`
	ServiceAccounts  int    `json:"serviceAccounts"`
	Workloads        int    `json:"workloads"`
	Assets           int    `json:"assets"`
	SecurityControls int    `json:"securityControls"`
	Warnings         int    `json:"warnings"`
}

func newSnapshotCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	command := &cobra.Command{Use: "snapshot", Short: "Save or inspect a credential-free cluster snapshot", Args: cobra.NoArgs}
	command.AddCommand(newSnapshotSaveCommand(streams, dependencies, state))
	command.AddCommand(newSnapshotInspectCommand(streams, state))
	return command
}

func newSnapshotSaveCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var file string
	var strict bool
	command := &cobra.Command{
		Use:   "save",
		Short: "Collect live cluster metadata and save canonical JSON",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if state.result.Config.Snapshot != "" {
				return apperr.New(apperr.KindValidation, "cli.snapshot.save", "snapshot save requires a live cluster; remove --snapshot", nil)
			}
			collect := dependencies.CollectSnapshot
			if collect == nil {
				collect = app.CollectLiveSnapshot
			}
			ctx, cancel := context.WithTimeout(command.Context(), state.result.Config.Timeout)
			defer cancel()
			value, err := collect(ctx, state.result.Config, dependencies.Version.Version)
			if err != nil {
				return apperr.Wrap("cli.snapshot.save", err)
			}
			if strict && len(value.Warnings) > 0 {
				return apperr.New(apperr.KindPartialCollection, "cli.snapshot.save", fmt.Sprintf("collection is incomplete: %d warning(s)", len(value.Warnings)), nil)
			}
			if err := snapshot.Save(file, value); err != nil {
				return apperr.New(apperr.KindOperational, "cli.snapshot.save", fmt.Sprintf("cannot save snapshot to %q", file), err)
			}
			return writeSnapshotResult(streams.Out, state.result.Config.Output, file, value)
		},
	}
	command.Flags().StringVarP(&file, "file", "o", "rbacviz-snapshot.json", "snapshot destination")
	command.Flags().BoolVar(&strict, "strict", false, "reject partial collection with exit code 3")
	return command
}

func newSnapshotInspectCommand(streams IOStreams, state *commandState) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file>",
		Short: "Validate a snapshot and print its inventory",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			value, err := snapshot.Load(args[0])
			if err != nil {
				return apperr.New(apperr.KindValidation, "cli.snapshot.inspect", fmt.Sprintf("invalid snapshot %q", args[0]), err)
			}
			return writeSnapshotResult(streams.Out, state.result.Config.Output, args[0], value)
		},
	}
}

func writeSnapshotResult(writer io.Writer, output, file string, value snapshot.Snapshot) error {
	summary := summarizeSnapshot(value)
	if output == "json" {
		payload := struct {
			File    string          `json:"file"`
			Summary snapshotSummary `json:"summary"`
		}{File: file, Summary: summary}
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			return apperr.New(apperr.KindOperational, "cli.snapshot.output", "cannot write snapshot output", err)
		}
		return nil
	}
	_, err := fmt.Fprintf(writer, "snapshot: %s\nschema: %s\ncomplete: %t\napi resources: %d\nidentities: %d\nroles: %d\nbindings: %d\nservice accounts: %d\nworkloads: %d\nassets: %d\nsecurity controls: %d\nwarnings: %d\n",
		file, summary.SchemaVersion, summary.Complete, summary.APIResources, summary.Identities, summary.Roles, summary.Bindings, summary.ServiceAccounts, summary.Workloads, summary.Assets, summary.SecurityControls, summary.Warnings)
	if err != nil {
		return apperr.New(apperr.KindOperational, "cli.snapshot.output", "cannot write snapshot output", err)
	}
	return nil
}

func summarizeSnapshot(value snapshot.Snapshot) snapshotSummary {
	return snapshotSummary{SchemaVersion: value.SchemaVersion, Complete: value.Metadata.Complete, APIResources: len(value.APIResources), Identities: len(value.Identities), Roles: len(value.Roles), Bindings: len(value.Bindings), ServiceAccounts: len(value.ServiceAccounts), Workloads: len(value.Workloads), Assets: len(value.Assets), SecurityControls: len(value.SecurityControls), Warnings: len(value.Warnings)}
}

func newVersionCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := version.Write(streams.Out, state.result.Config.Output, dependencies.Version); err != nil {
				return apperr.New(apperr.KindOperational, "cli.version", "cannot write version output", err)
			}
			return nil
		},
	}
}

func newConfigCommand(streams IOStreams, state *commandState) *cobra.Command {
	var showSources bool
	command := &cobra.Command{
		Use:   "config",
		Short: "Print the validated effective configuration",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if state.result.Config.Output == "json" {
				payload := any(state.result.Config)
				if showSources {
					payload = state.result
				}
				encoder := json.NewEncoder(streams.Out)
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(payload); err != nil {
					return apperr.New(apperr.KindOperational, "cli.config", "cannot write configuration output", err)
				}
				return nil
			}
			return writeHumanConfig(streams.Out, state.result, showSources)
		},
	}
	command.Flags().BoolVar(&showSources, "show-sources", false, "show the origin of every effective value")
	return command
}

func loadConfig(command *cobra.Command, flags rawFlags, dependencies Dependencies) (config.Result, error) {
	path := flags.configPath
	required := command.Flags().Changed("config")
	if !required && dependencies.LookupEnv != nil {
		if environmentPath, ok := dependencies.LookupEnv("RBACVIZ_CONFIG"); ok {
			path = environmentPath
			required = true
		}
	}
	if path == "" {
		defaultPath, err := config.DefaultPath(dependencies.UserConfigDir)
		if err != nil {
			return config.Result{}, err
		}
		path = defaultPath
	}

	result, err := config.Load(config.LoadOptions{
		FilePath: path, FileRequired: required, LookupEnv: dependencies.LookupEnv,
		Overrides: config.Overrides{
			Context:       changedString(command, "context", flags.context),
			Kubeconfig:    changedString(command, "kubeconfig", flags.kubeconfig),
			Namespace:     changedString(command, "namespace", flags.namespace),
			AllNamespaces: changedBool(command, "all-namespaces", flags.allNamespaces),
			Snapshot:      changedString(command, "snapshot", flags.snapshot),
			Output:        changedString(command, "output", flags.output),
			NoColor:       changedBool(command, "no-color", flags.noColor),
			Timeout:       changedDuration(command, "timeout", flags.timeout),
			LogLevel:      changedString(command, "log-level", flags.logLevel),
		},
	})
	if err != nil {
		return config.Result{}, apperr.Wrap("cli.config", err)
	}
	return result, nil
}

func changedString(command *cobra.Command, name, value string) *string {
	if command.Flags().Changed(name) {
		return &value
	}
	return nil
}

func changedBool(command *cobra.Command, name string, value bool) *bool {
	if command.Flags().Changed(name) {
		return &value
	}
	return nil
}

func changedDuration(command *cobra.Command, name string, value time.Duration) *time.Duration {
	if command.Flags().Changed(name) {
		return &value
	}
	return nil
}

func writeHumanConfig(writer io.Writer, result config.Result, showSources bool) error {
	values := map[string]string{
		"allNamespaces": fmt.Sprintf("%t", result.Config.AllNamespaces),
		"context":       result.Config.Context,
		"kubeconfig":    result.Config.Kubeconfig,
		"logLevel":      result.Config.LogLevel,
		"namespace":     result.Config.Namespace,
		"noColor":       fmt.Sprintf("%t", result.Config.NoColor),
		"output":        result.Config.Output,
		"snapshot":      result.Config.Snapshot,
		"timeout":       result.Config.Timeout.String(),
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if showSources {
			if _, err := fmt.Fprintf(writer, "%s: %s (%s)\n", key, values[key], result.Sources[key]); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(writer, "%s: %s\n", key, values[key]); err != nil {
			return err
		}
	}
	return nil
}
