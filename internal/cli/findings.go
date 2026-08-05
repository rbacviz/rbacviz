package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/sarif"
)

func newFindingsCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var severities, ruleIDs []string
	command := &cobra.Command{
		Use: "findings", Short: "Detect evidence-backed dangerous configurations", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			severityFilter, err := parseSeverities(severities)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.findings.severity", err.Error(), err)
			}
			result, err := analyzeFindings(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			result.Findings = filterFindings(result.Findings, severityFilter, canonicalUpper(ruleIDs), state.result.Config.Namespace)
			return writeFindings(streams.Out, state.result.Config.Output, result)
		},
	}
	command.Flags().StringSliceVar(&severities, "severity", nil, "severity filter: critical, high, medium, low, or info")
	command.Flags().StringSliceVar(&ruleIDs, "rule", nil, "stable rule ID filter (repeatable or comma-separated)")
	return command
}

func newExplainCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	return &cobra.Command{
		Use: "explain <finding-id>", Short: "Explain one finding and all of its evidence", Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			result, err := analyzeFindings(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			wanted := strings.ToUpper(strings.TrimSpace(args[0]))
			for _, finding := range result.Findings {
				if finding.ID == wanted {
					result.Findings = []analysis.Finding{finding}
					return writeFindingExplanation(streams.Out, state.result.Config.Output, result)
				}
			}
			return apperr.New(apperr.KindInvalidInput, "cli.explain.id", fmt.Sprintf("finding %q was not found in this analysis", args[0]), nil)
		},
	}
}

func analyzeFindings(ctx context.Context, dependencies Dependencies, state *commandState) (analysis.Result, error) {
	value, err := loadAnalysisSnapshot(ctx, dependencies, state)
	if err != nil {
		return analysis.Result{}, err
	}
	analyzer, err := app.NewFindingsAnalyzer(value)
	if err != nil {
		return analysis.Result{}, apperr.New(apperr.KindValidation, "cli.findings.build", "cannot initialize findings analysis", err)
	}
	result, err := analyzer.Analyze(ctx)
	if err != nil {
		return analysis.Result{}, apperr.New(apperr.KindOperational, "cli.findings.analyze", "findings analysis failed", err)
	}
	return result, nil
}

func writeFindings(writer io.Writer, output string, result analysis.Result) error {
	switch output {
	case "json":
		return writeFindingsJSON(writer, result)
	case "sarif":
		if err := sarif.Write(writer, result); err != nil {
			return findingsOutputError(err)
		}
		return nil
	}
	counts := findingCounts(result.Findings)
	if _, err := fmt.Fprintf(writer, "ruleset: %s\ncomplete: %t\nfindings: %d\ncritical: %d\nhigh: %d\nmedium: %d\nlow: %d\ninfo: %d\nwarnings: %d\n", result.RulesetVersion, result.Complete, len(result.Findings), counts[analysis.SeverityCritical], counts[analysis.SeverityHigh], counts[analysis.SeverityMedium], counts[analysis.SeverityLow], counts[analysis.SeverityInfo], len(result.Warnings)); err != nil {
		return findingsOutputError(err)
	}
	for _, finding := range result.Findings {
		if _, err := fmt.Fprintf(writer, "- [%s] %s %s\n  %s\n  identity: %s\n  objects: %d evidence: %d confidence: %s score: %d\n", finding.Severity, finding.ID, finding.Title, finding.Description, identityList(finding.AffectedIdentities), len(finding.AffectedObjects), len(finding.Evidence), finding.Confidence, finding.RiskScore); err != nil {
			return findingsOutputError(err)
		}
	}
	return writeFindingWarnings(writer, result.Warnings)
}

func writeFindingExplanation(writer io.Writer, output string, result analysis.Result) error {
	if output != "human" {
		return writeFindings(writer, output, result)
	}
	finding := result.Findings[0]
	if _, err := fmt.Fprintf(writer, "finding: %s\nrule: %s\ntitle: %s\nseverity: %s\nrisk score: %d\nconfidence: %s\ndescription: %s\nsecurity impact: %s\n", finding.ID, finding.RuleID, finding.Title, finding.Severity, finding.RiskScore, finding.Confidence, finding.Description, finding.SecurityImpact); err != nil {
		return findingsOutputError(err)
	}
	for _, identity := range finding.AffectedIdentities {
		if _, err := fmt.Fprintf(writer, "affected identity: %s\n", identityStringCLI(identity)); err != nil {
			return findingsOutputError(err)
		}
	}
	for _, object := range finding.AffectedObjects {
		if _, err := fmt.Fprintf(writer, "affected object: %s %s\n", object.Kind, qualifiedRef(object)); err != nil {
			return findingsOutputError(err)
		}
	}
	for _, evidence := range finding.Evidence {
		ref := ""
		if evidence.Ref != nil {
			ref = evidence.Ref.Kind + " " + qualifiedRef(*evidence.Ref)
		}
		if _, err := fmt.Fprintf(writer, "evidence: %s %s field=%s value=%s\n", evidence.Kind, ref, evidence.Field, evidence.Value); err != nil {
			return findingsOutputError(err)
		}
		if evidence.Permission != nil {
			if _, err := fmt.Fprintf(writer, "  permission: %s\n", permissionEvidenceString(*evidence.Permission)); err != nil {
				return findingsOutputError(err)
			}
		}
		if evidence.Grant != nil {
			if _, err := fmt.Fprintf(writer, "  grant: %s via %s %s -> %s %s\n", evidence.Grant.ID, evidence.Grant.BindingRef.Kind, qualifiedRef(evidence.Grant.BindingRef), evidence.Grant.RoleRef.Kind, qualifiedRef(evidence.Grant.RoleRef)); err != nil {
				return findingsOutputError(err)
			}
		}
	}
	for _, recommendation := range finding.Recommendations {
		if _, err := fmt.Fprintf(writer, "recommendation: %s\n", recommendation); err != nil {
			return findingsOutputError(err)
		}
	}
	for _, reference := range finding.References {
		if _, err := fmt.Fprintf(writer, "reference: %s\n", reference); err != nil {
			return findingsOutputError(err)
		}
	}
	return writeFindingWarnings(writer, result.Warnings)
}

func filterFindings(values []analysis.Finding, severities map[analysis.Severity]struct{}, ruleIDs map[string]struct{}, namespace string) []analysis.Finding {
	result := make([]analysis.Finding, 0, len(values))
	for _, value := range values {
		if len(severities) > 0 {
			if _, ok := severities[value.Severity]; !ok {
				continue
			}
		}
		if len(ruleIDs) > 0 {
			if _, ok := ruleIDs[value.RuleID]; !ok {
				continue
			}
		}
		if namespace != "" && !findingAffectsNamespace(value, namespace) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func findingAffectsNamespace(value analysis.Finding, namespace string) bool {
	for _, object := range value.AffectedObjects {
		if object.Namespace == namespace || object.Kind == "ClusterRoleBinding" {
			return true
		}
	}
	for _, identity := range value.AffectedIdentities {
		if identity.Namespace == namespace {
			return true
		}
	}
	for _, evidence := range value.Evidence {
		if evidence.Permission != nil && (evidence.Permission.Namespace == namespace || evidence.Permission.Namespace == "*" || evidence.Permission.Scope == permission.ScopeCluster) {
			return true
		}
	}
	return false
}

func parseSeverities(values []string) (map[analysis.Severity]struct{}, error) {
	result := make(map[analysis.Severity]struct{}, len(values))
	for _, value := range values {
		severity := analysis.Severity(strings.ToUpper(strings.TrimSpace(value)))
		switch severity {
		case analysis.SeverityCritical, analysis.SeverityHigh, analysis.SeverityMedium, analysis.SeverityLow, analysis.SeverityInfo:
			result[severity] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid severity %q; expected critical, high, medium, low, or info", value)
		}
	}
	return result, nil
}

func writeFindingsJSON(writer io.Writer, result analysis.Result) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return findingsOutputError(err)
	}
	return nil
}

func findingCounts(values []analysis.Finding) map[analysis.Severity]int {
	result := make(map[analysis.Severity]int)
	for _, value := range values {
		result[value.Severity]++
	}
	return result
}

func canonicalUpper(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[strings.ToUpper(strings.TrimSpace(value))] = struct{}{}
	}
	return result
}

func identityList(values []permission.Identity) string {
	if len(values) == 0 {
		return "-"
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, identityStringCLI(value))
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func identityStringCLI(value permission.Identity) string {
	if value.Kind == "ServiceAccount" {
		return "serviceaccount:" + value.Namespace + ":" + value.Name
	}
	return strings.ToLower(string(value.Kind)) + ":" + value.Name
}

func permissionEvidenceString(value analysis.PermissionEvidence) string {
	target := value.Resource
	if value.Subresource != "" {
		target += "/" + value.Subresource
	}
	if value.APIGroup != "" {
		target += "." + value.APIGroup
	}
	if value.NonResourceURL != "" {
		target = value.NonResourceURL
	}
	return value.Verb + " " + target + " scope=" + string(value.Scope) + " namespace=" + value.Namespace
}

func writeFindingWarnings(writer io.Writer, warnings []analysis.Warning) error {
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(writer, "warning: %s: %s\n", warning.Code, warning.Message); err != nil {
			return findingsOutputError(err)
		}
	}
	return nil
}

func findingsOutputError(err error) error {
	return apperr.New(apperr.KindOperational, "cli.findings.output", "cannot write findings output", err)
}
