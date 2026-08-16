package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
)

func newRiskCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var identity string
	var top, maxPaths, maxExpanded int
	var includePaths bool
	command := &cobra.Command{
		Use: "risk", Short: "Score attack paths and aggregate identity, namespace, and cluster risk", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if top < 1 || top > 100 {
				return apperr.New(apperr.KindInvalidInput, "cli.risk.top", "--top must be between 1 and 100", nil)
			}
			query, err := parseRiskQuery(identity, state.result.Config.Namespace, maxPaths, maxExpanded, includePaths)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.risk.query", err.Error(), err)
			}
			result, err := analyzeRisk(command.Context(), dependencies, state, query)
			if err != nil {
				return err
			}
			return writeRisk(streams.Out, state.result.Config.Output, result, top)
		},
	}
	command.Flags().StringVar(&identity, "identity", "", "limit analysis to user:<name>, group:<name>, or serviceaccount:<namespace>:<name>")
	command.Flags().IntVar(&top, "top", 10, "maximum paths, identities, and namespaces in human output (1-100)")
	command.Flags().IntVar(&maxPaths, "max-paths", 10000, "maximum attack paths included in scoring")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 100000, "maximum attack template candidates to expand")
	command.Flags().BoolVar(&includePaths, "include-paths", false, "embed full attack-path evidence in JSON path scores")
	return command
}

func parseRiskQuery(identity, namespace string, maxPaths, maxExpanded int, includePaths bool) (risk.Query, error) {
	if maxPaths < 1 || maxPaths > 100000 {
		return risk.Query{}, fmt.Errorf("--max-paths must be between 1 and 100000")
	}
	if maxExpanded < 1 {
		return risk.Query{}, fmt.Errorf("--max-expanded must be at least 1")
	}
	query := risk.Query{Namespace: namespace, MaxPaths: maxPaths, MaxExpanded: maxExpanded, IncludePath: includePaths}
	if strings.TrimSpace(identity) != "" {
		value, err := permission.ParseIdentity(identity)
		if err != nil {
			return risk.Query{}, err
		}
		query.From = &value
	}
	return query, nil
}

func analyzeRisk(ctx context.Context, dependencies Dependencies, state *commandState, query risk.Query) (risk.Result, error) {
	value, err := loadAnalysisSnapshot(ctx, dependencies, state)
	if err != nil {
		return risk.Result{}, err
	}
	analyzer, err := app.NewRiskAnalyzer(value)
	if err != nil {
		return risk.Result{}, apperr.New(apperr.KindValidation, "cli.risk.build", "cannot initialize risk analysis", err)
	}
	result, err := analyzer.Analyze(ctx, query)
	if err != nil {
		return risk.Result{}, apperr.New(apperr.KindOperational, "cli.risk.analyze", "risk analysis failed", err)
	}
	return result, nil
}

func writeRisk(writer io.Writer, output string, result risk.Result, top int) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return riskOutputError(err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer, "risk model: %s\ncomplete: %t\ntruncated: %t\ncluster risk: %d %s\nnotice: cluster risk is a posture index, not breach probability\npaths: %d root-cause-families: %d identities: %d namespaces: %d warnings: %d\n",
		result.ModelVersion, result.Complete, result.Truncated, result.Cluster.Score, result.Cluster.Severity,
		len(result.PathScores), len(result.RiskFamilies), len(result.Identities), len(result.Namespaces), len(result.Warnings)); err != nil {
		return riskOutputError(err)
	}
	if err := writeRiskAggregates(writer, "identity", result.Identities, top); err != nil {
		return err
	}
	if err := writeRiskAggregates(writer, "namespace", result.Namespaces, top); err != nil {
		return err
	}
	limit := smallerCLI(top, len(result.RiskFamilies))
	for index := 0; index < limit; index++ {
		family := result.RiskFamilies[index]
		if _, err := fmt.Fprintf(writer, "risk family %d: %d %s %s\n  family id: %s\n  source: %s\n  paths: %d semantic-units: %d confidence=%s blocked=%t\n",
			index+1, family.Score, family.Severity, family.RootCause, family.ID, family.Source.String(),
			family.PathCount, family.DistinctRiskUnits, family.Confidence, family.Blocked); err != nil {
			return riskOutputError(err)
		}
	}
	limit = smallerCLI(top, len(result.PathScores))
	for index := 0; index < limit; index++ {
		value := result.PathScores[index]
		if _, err := fmt.Fprintf(writer, "path risk %d: %d %s %s [%s]\n  risk id: %s\n  path id: %s\n  source: %s\n  target: %s namespace=%s confidence=%s blocked=%t\n  scope factor: %d bps mitigation: %d bps\n",
			index+1, value.Score, value.Severity, value.Title, value.TemplateID, value.ID, value.PathID,
			value.Source.String(), value.Target.Type, value.Target.Namespace, value.Confidence, value.Blocked,
			value.ScopeFactorBPS, value.Mitigation.EffectBasisPts); err != nil {
			return riskOutputError(err)
		}
		for _, factor := range value.Factors {
			if _, err := fmt.Fprintf(writer, "  factor: %s value=%d weight=%d%% contribution=%d source=%s\n", factor.Name, factor.Value, factor.Weight, factor.Contribution, factor.Source); err != nil {
				return riskOutputError(err)
			}
		}
		if _, err := fmt.Fprintf(writer, "  formula: weightedTotal=%d scopeBPS=%d mitigationBPS=%d numerator=%d denominator=%d\n",
			value.Formula.WeightedTotal, value.Formula.ScopeFactorBasisPts, value.Formula.MitigationBasisPts,
			value.Formula.Numerator, value.Formula.Denominator); err != nil {
			return riskOutputError(err)
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(writer, "warning: %s: %s\n", warning.Code, warning.Message); err != nil {
			return riskOutputError(err)
		}
	}
	return nil
}

func writeRiskAggregates(writer io.Writer, label string, values []risk.AggregateScore, top int) error {
	limit := smallerCLI(top, len(values))
	for index := 0; index < limit; index++ {
		value := values[index]
		if _, err := fmt.Fprintf(writer, "%s risk %d: %s score=%d severity=%s paths=%d risk-units=%d root-families=%d contributors=%d primary=%d additional=%d\n",
			label, index+1, value.Key, value.Score, value.Severity, value.PathCount,
			value.DistinctRiskUnits, value.RiskFamilyCount, value.ContributingFamilies,
			value.PrimaryScore, value.AdditionalContribution); err != nil {
			return riskOutputError(err)
		}
	}
	return nil
}

func smallerCLI(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func riskOutputError(err error) error {
	return apperr.New(apperr.KindOperational, "cli.risk.output", "cannot write risk output", err)
}
