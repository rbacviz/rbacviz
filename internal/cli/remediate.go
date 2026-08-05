package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/remediation"
)

func newRemediateCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var identity string
	var top, maxCandidates, maxPaths, maxExpanded int
	var includeDominated, includeDiff bool
	command := &cobra.Command{
		Use: "remediate", Aliases: []string{"remediation"}, Short: "Generate and virtually rank advisory remediation candidates", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if top < 1 || top > 100 {
				return apperr.New(apperr.KindInvalidInput, "cli.remediate.top", "--top must be between 1 and 100", nil)
			}
			options, err := remediationOptions(identity, state.result.Config.Namespace, maxCandidates, maxPaths, maxExpanded, includeDominated, includeDiff)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.remediate.options", err.Error(), err)
			}
			value, err := loadAnalysisSnapshot(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			result, err := app.GenerateRemediations(command.Context(), value, options)
			if err != nil {
				return apperr.New(apperr.KindOperational, "cli.remediate.analyze", "remediation analysis failed", err)
			}
			return writeRemediation(streams.Out, state.result.Config.Output, result, top, includeDominated)
		},
	}
	command.Flags().StringVar(&identity, "identity", "", "limit candidates to paths from user:<name>, group:<name>, or serviceaccount:<namespace>:<name>")
	command.Flags().IntVar(&top, "top", 10, "maximum candidates in human output (1-100)")
	command.Flags().IntVar(&maxCandidates, "max-candidates", 250, "maximum candidates to virtually evaluate")
	command.Flags().IntVar(&maxPaths, "max-paths", 10000, "maximum baseline attack paths used for candidate generation")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 100000, "maximum attack template candidates expanded per analysis")
	command.Flags().BoolVar(&includeDominated, "include-dominated", false, "include Pareto-dominated candidates in output")
	command.Flags().BoolVar(&includeDiff, "include-diff", false, "embed the complete semantic diff for each returned candidate in JSON")
	return command
}

func remediationOptions(identity, namespace string, maxCandidates, maxPaths, maxExpanded int, includeDominated, includeDiff bool) (remediation.Options, error) {
	if maxCandidates < 1 || maxCandidates > 10000 {
		return remediation.Options{}, fmt.Errorf("--max-candidates must be between 1 and 10000")
	}
	if maxPaths < 1 || maxPaths > 100000 {
		return remediation.Options{}, fmt.Errorf("--max-paths must be between 1 and 100000")
	}
	if maxExpanded < 1 {
		return remediation.Options{}, fmt.Errorf("--max-expanded must be at least 1")
	}
	options := remediation.Options{Namespace: namespace, MaxCandidates: maxCandidates, MaxPaths: maxPaths, MaxExpanded: maxExpanded, IncludeDominated: includeDominated, IncludeDiff: includeDiff}
	if strings.TrimSpace(identity) != "" {
		value, err := permission.ParseIdentity(identity)
		if err != nil {
			return remediation.Options{}, err
		}
		options.Identity = &value
	}
	return options, nil
}

func writeRemediation(writer io.Writer, output string, result remediation.Result, top int, includeDominated bool) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return remediationOutputError(err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer,
		"remediation model: %s\ncomplete: %t\ntruncated: %t\nbaseline cluster risk: %d %s\ncandidates: generated=%d evaluated=%d recommended=%d dominated=%d ineffective=%d\nbest simulated cluster risk: %d\n",
		result.ModelVersion, result.Complete, result.Truncated, result.BaselineRisk.Score, result.BaselineRisk.Severity,
		result.Summary.Generated, result.Summary.Evaluated, result.Summary.Recommended, result.Summary.Dominated, result.Summary.Ineffective,
		result.Summary.BestRiskAfter); err != nil {
		return remediationOutputError(err)
	}
	written := 0
	for _, candidate := range result.Candidates {
		if !includeDominated && candidate.Disposition == remediation.DispositionDominated {
			continue
		}
		if written >= top {
			break
		}
		written++
		if _, err := fmt.Fprintf(writer,
			"candidate %d: %s [%s]\n  id: %s\n  action: %s %s/%s\n  benefit: %d cost: %d ratio: %d bps pareto=%t\n  paths: removed=%d blocked=%d remaining=%d\n  risk: %d -> %d (%+d)\n  permissions lost: %d affected identities: %d\n  reason: %s\n",
			written, candidate.Title, candidate.Disposition, candidate.ID, candidate.Kind, candidate.Change.Ref.Namespace, candidate.Change.Ref.Name,
			candidate.Benefit.Total, candidate.Cost.Total, candidate.Ranking.BenefitCostBasis, candidate.Ranking.ParetoOptimal,
			len(candidate.Impact.RemovedPathIDs), len(candidate.Impact.BlockedPathIDs), candidate.Impact.RemainingAttackPaths,
			candidate.Impact.Risk.Cluster.Before, candidate.Impact.Risk.Cluster.After, candidate.Impact.Risk.Cluster.Delta,
			len(candidate.Impact.LostCapabilities), len(candidate.Impact.AffectedIdentities), candidate.Reason); err != nil {
			return remediationOutputError(err)
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(writer, "warning: %s: %s\n", warning.Code, warning.Message); err != nil {
			return remediationOutputError(err)
		}
	}
	return nil
}

func remediationOutputError(err error) error {
	return apperr.New(apperr.KindOperational, "cli.remediate.output", "cannot write remediation output", err)
}
