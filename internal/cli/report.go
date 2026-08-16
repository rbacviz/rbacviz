package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/report"
	"github.com/rbacviz/rbacviz/internal/sarif"
)

func newReportCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var format, file, baselinePath string
	var maxIssues, maxCandidates, maxPaths, maxExpanded int
	command := &cobra.Command{
		Use: "report", Short: "Generate a prioritized, root-cause-oriented security report", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			format = strings.ToLower(strings.TrimSpace(format))
			if format == "markdown" {
				format = "md"
			}
			if format != "md" && format != "json" && format != "sarif" {
				return apperr.New(apperr.KindInvalidInput, "cli.report.format", "--format must be md, markdown, json, or sarif", nil)
			}
			if maxIssues < 1 || maxIssues > 1000 {
				return apperr.New(apperr.KindInvalidInput, "cli.report.max-issues", "--max-issues must be between 1 and 1000", nil)
			}
			if maxCandidates < 1 || maxCandidates > 1000 {
				return apperr.New(apperr.KindInvalidInput, "cli.report.max-candidates", "--max-candidates must be between 1 and 1000", nil)
			}
			if maxPaths < 1 || maxPaths > 100000 {
				return apperr.New(apperr.KindInvalidInput, "cli.report.max-paths", "--max-paths must be between 1 and 100000", nil)
			}
			if maxExpanded < 1 {
				return apperr.New(apperr.KindInvalidInput, "cli.report.max-expanded", "--max-expanded must be at least 1", nil)
			}
			value, err := loadAnalysisSnapshot(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			var policy *baseline.Document
			if strings.TrimSpace(baselinePath) != "" {
				loaded, loadErr := baseline.Load(baselinePath)
				if loadErr != nil {
					return apperr.New(apperr.KindInvalidInput, "cli.report.baseline", loadErr.Error(), loadErr)
				}
				policy = &loaded
			}
			result, err := app.GenerateReport(command.Context(), value, report.Options{
				Namespace: state.result.Config.Namespace, MaxIssues: maxIssues,
				MaxCandidates: maxCandidates, MaxPaths: maxPaths, MaxExpanded: maxExpanded,
				Baseline: policy, EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
			})
			if err != nil {
				return apperr.New(apperr.KindOperational, "cli.report.analyze", "report analysis failed", err)
			}
			write := func(writer io.Writer) error { return writeReport(writer, format, result) }
			if file == "" || file == "-" {
				return write(streams.Out)
			}
			if err := writeReportFile(file, write); err != nil {
				return apperr.New(apperr.KindOperational, "cli.report.file", fmt.Sprintf("cannot write report to %q", file), err)
			}
			_, err = fmt.Fprintf(streams.Out, "report: %s\nformat: %s\nroot causes: %d\naccepted exceptions: %d\nrecommended fixes: %d\nrisk index: %d/100 %s\n", file, format, result.Summary.RootCauses, result.Summary.AcceptedExceptions, result.Summary.RecommendedFixes, result.Summary.RiskIndex, result.Summary.RiskSeverity)
			if err != nil {
				return apperr.New(apperr.KindOperational, "cli.report.output", "cannot write report summary", err)
			}
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", "md", "report format: md, json, or sarif")
	command.Flags().StringVarP(&file, "file", "f", "", "write report to a file; default is stdout")
	command.Flags().StringVar(&baselinePath, "baseline", "", "path to a reviewed YAML or JSON suppression baseline")
	command.Flags().IntVar(&maxIssues, "max-issues", 50, "maximum root-cause issues included in the report (1-1000)")
	command.Flags().IntVar(&maxCandidates, "max-candidates", 50, "maximum remediation candidates to virtually evaluate (1-1000)")
	command.Flags().IntVar(&maxPaths, "max-paths", 10000, "maximum attack paths included in report analysis")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 100000, "maximum attack template candidates expanded per analysis")
	return command
}

func writeReport(writer io.Writer, format string, result report.Result) error {
	if format == "sarif" {
		if err := sarif.WriteReport(writer, result); err != nil {
			return apperr.New(apperr.KindOperational, "cli.report.output", "cannot write SARIF report", err)
		}
		return nil
	}
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return apperr.New(apperr.KindOperational, "cli.report.output", "cannot write JSON report", err)
		}
		return nil
	}
	if err := report.WriteMarkdown(writer, result); err != nil {
		return apperr.New(apperr.KindOperational, "cli.report.output", "cannot write Markdown report", err)
	}
	return nil
}

func writeReportFile(path string, write func(io.Writer) error) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".rbacviz-report-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := write(temporary); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}
