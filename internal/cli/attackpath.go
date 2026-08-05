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
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
)

func newAttackPathCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var from, to string
	var top, maxExpanded int
	command := &cobra.Command{
		Use: "attack-path", Short: "Find evidence-backed Kubernetes privilege-escalation paths", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			query, err := parseAttackPathQuery(from, to, state.result.Config.Namespace, top, maxExpanded)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.attack-path.query", err.Error(), err)
			}
			result, err := analyzeAttackPaths(command.Context(), dependencies, state, query)
			if err != nil {
				return err
			}
			return writeAttackPaths(streams.Out, state.result.Config.Output, result)
		},
	}
	command.Flags().StringVar(&from, "from", "", "source identity: user:<name>, group:<name>, or serviceaccount:<namespace>:<name>")
	command.Flags().StringVar(&to, "to", "", "privilege target, for example cluster-admin or host-escape")
	command.Flags().IntVar(&top, "top", 10, "maximum ranked paths to print (1-100)")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 50000, "maximum matching template candidates to expand")
	return command
}

func parseAttackPathQuery(from, to, namespace string, top, maxExpanded int) (attackpath.Query, error) {
	if top < 1 || top > 100 {
		return attackpath.Query{}, fmt.Errorf("--top must be between 1 and 100")
	}
	if maxExpanded < 1 {
		return attackpath.Query{}, fmt.Errorf("--max-expanded must be at least 1")
	}
	query := attackpath.Query{Namespace: namespace, Top: top, MaxExpanded: maxExpanded}
	if strings.TrimSpace(from) != "" {
		identity, err := permission.ParseIdentity(from)
		if err != nil {
			return attackpath.Query{}, err
		}
		query.From = &identity
	}
	if strings.TrimSpace(to) != "" {
		target, err := attackpath.ParseTarget(to)
		if err != nil {
			return attackpath.Query{}, err
		}
		query.To = &target
	}
	return query, nil
}

func analyzeAttackPaths(ctx context.Context, dependencies Dependencies, state *commandState, query attackpath.Query) (attackpath.Result, error) {
	value, err := loadAnalysisSnapshot(ctx, dependencies, state)
	if err != nil {
		return attackpath.Result{}, err
	}
	analyzer, err := app.NewAttackPathAnalyzer(value)
	if err != nil {
		return attackpath.Result{}, apperr.New(apperr.KindValidation, "cli.attack-path.build", "cannot initialize attack-path analysis", err)
	}
	result, err := analyzer.Analyze(ctx, query)
	if err != nil {
		return attackpath.Result{}, apperr.New(apperr.KindOperational, "cli.attack-path.analyze", "attack-path analysis failed", err)
	}
	return result, nil
}

func writeAttackPaths(writer io.Writer, output string, result attackpath.Result) error {
	if output == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return attackPathOutputError(err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer, "template set: %s\ncomplete: %t\npaths: %d\nexpanded: %d\ntruncated: %t\nwarnings: %d\n", result.TemplateSetVersion, result.Complete, len(result.Paths), result.Expanded, result.Truncated, len(result.Warnings)); err != nil {
		return attackPathOutputError(err)
	}
	for index, path := range result.Paths {
		if _, err := fmt.Fprintf(writer, "path %d: %s [%s] cost=%d confidence=%s blocked=%t\n  id: %s\n  source: %s\n  target: %s namespace=%s\n", index+1, path.Title, path.TemplateID, path.Cost, path.Confidence, path.Blocked, path.ID, path.Source.String(), path.Target.Type, path.Target.Namespace); err != nil {
			return attackPathOutputError(err)
		}
		for _, reason := range path.ConfidenceReasons {
			if _, err := fmt.Fprintf(writer, "  confidence reason: %s\n", reason); err != nil {
				return attackPathOutputError(err)
			}
		}
		for _, step := range path.Steps {
			if err := writeAttackStep(writer, step); err != nil {
				return err
			}
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(writer, "warning: %s: %s\n", warning.Code, warning.Message); err != nil {
			return attackPathOutputError(err)
		}
	}
	return nil
}

func writeAttackStep(writer io.Writer, step attackpath.AttackStep) error {
	if _, err := fmt.Fprintf(writer, "  step: %s --%s--> %s\n    technique: %s cost=%d confidence=%s\n", step.From.Key, step.Relation, step.To.Key, step.TechniqueID, step.Cost.Total, step.Confidence); err != nil {
		return attackPathOutputError(err)
	}
	for _, evidence := range step.Evidence {
		if evidence.Permission != nil {
			permissionValue := evidence.Permission
			if _, err := fmt.Fprintf(writer, "    permission: %s %s%s group=%s scope=%s namespace=%s resourceNames=%s\n", permissionValue.Verb, permissionValue.Resource, subresourceSuffix(permissionValue.Subresource), permissionValue.APIGroup, permissionValue.Scope, permissionValue.Namespace, strings.Join(permissionValue.ResourceNames, ",")); err != nil {
				return attackPathOutputError(err)
			}
		}
		if evidence.Grant != nil {
			grant := evidence.Grant
			if _, err := fmt.Fprintf(writer, "    grant: %s rule=%s via %s %s -> %s %s\n", grant.ID, grant.PolicyRuleID, grant.BindingRef.Kind, qualifiedRef(grant.BindingRef), grant.RoleRef.Kind, qualifiedRef(grant.RoleRef)); err != nil {
				return attackPathOutputError(err)
			}
		}
		if evidence.Ref != nil {
			if _, err := fmt.Fprintf(writer, "    object: %s %s field=%s value=%s\n", evidence.Ref.Kind, qualifiedRef(*evidence.Ref), evidence.Field, evidence.Value); err != nil {
				return attackPathOutputError(err)
			}
		}
	}
	for _, prerequisite := range step.Prerequisites {
		if _, err := fmt.Fprintf(writer, "    prerequisite: %s [%s] %s\n", prerequisite.ID, prerequisite.State, prerequisite.Description); err != nil {
			return attackPathOutputError(err)
		}
	}
	for _, control := range step.MitigatingControls {
		if _, err := fmt.Fprintf(writer, "    mitigation: %s [%s] known=%t %s\n", control.ControlType, control.State, control.SemanticsKnown, control.Reason); err != nil {
			return attackPathOutputError(err)
		}
	}
	for _, remediation := range step.RemediationCandidates {
		if _, err := fmt.Fprintf(writer, "    remediation candidate: %s\n", remediation); err != nil {
			return attackPathOutputError(err)
		}
	}
	return nil
}

func subresourceSuffix(value string) string {
	if value == "" {
		return ""
	}
	return "/" + value
}

func attackPathOutputError(err error) error {
	return apperr.New(apperr.KindOperational, "cli.attack-path.output", "cannot write attack-path output", err)
}
