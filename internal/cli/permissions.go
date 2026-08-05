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
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func newPermissionsCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var groups []string
	command := &cobra.Command{
		Use:   "permissions <identity>",
		Short: "List effective RBAC permissions with full grant provenance",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			identity, err := permission.ParseIdentity(args[0])
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.permissions.identity", err.Error(), err)
			}
			resolver, err := loadPermissionResolver(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			return writePermissions(streams.Out, state.result.Config.Output, resolver.Permissions(identity, groups))
		},
	}
	command.Flags().StringSliceVar(&groups, "as-group", nil, "explicit group membership for a User query (repeatable)")
	return command
}

func newWhoCanCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var apiGroup string
	var resourceName string
	command := &cobra.Command{
		Use:   "who-can <verb> <resource>",
		Short: "List RBAC subjects that can perform an action",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			action, err := actionFromArgs(args[0], args[1], apiGroup, state.result.Config.Namespace, resourceName)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.who-can.action", err.Error(), err)
			}
			resolver, err := loadPermissionResolver(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			return writeWhoCan(streams.Out, state.result.Config.Output, resolver.WhoCan(action))
		},
	}
	command.Flags().StringVar(&apiGroup, "api-group", "", "API group when it is not encoded in the resource argument")
	command.Flags().StringVar(&resourceName, "resource-name", "", "match access to one named resource")
	return command
}

func newWhyCanCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var apiGroup string
	var resourceName string
	var groups []string
	command := &cobra.Command{
		Use:   "why-can <identity> <verb> <resource>",
		Short: "Explain every RBAC grant for an identity and action",
		Args:  cobra.ExactArgs(3),
		RunE: func(command *cobra.Command, args []string) error {
			identity, err := permission.ParseIdentity(args[0])
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.why-can.identity", err.Error(), err)
			}
			action, err := actionFromArgs(args[1], args[2], apiGroup, state.result.Config.Namespace, resourceName)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.why-can.action", err.Error(), err)
			}
			resolver, err := loadPermissionResolver(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			return writeWhyCan(streams.Out, state.result.Config.Output, resolver.WhyCan(identity, groups, action))
		},
	}
	command.Flags().StringVar(&apiGroup, "api-group", "", "API group when it is not encoded in the resource argument")
	command.Flags().StringVar(&resourceName, "resource-name", "", "match access to one named resource")
	command.Flags().StringSliceVar(&groups, "as-group", nil, "explicit group membership for a User query (repeatable)")
	return command
}

func loadPermissionResolver(ctx context.Context, dependencies Dependencies, state *commandState) (*app.PermissionAnalyzer, error) {
	value, err := loadAnalysisSnapshot(ctx, dependencies, state)
	if err != nil {
		return nil, err
	}
	resolver, err := app.NewPermissionAnalyzer(value)
	if err != nil {
		return nil, apperr.New(apperr.KindValidation, "cli.permissions.resolve", "cannot initialize permission resolver", err)
	}
	return resolver, nil
}

func loadAnalysisSnapshot(ctx context.Context, dependencies Dependencies, state *commandState) (snapshot.Snapshot, error) {
	if state.result.Config.Snapshot != "" {
		value, err := snapshot.Load(state.result.Config.Snapshot)
		if err != nil {
			return snapshot.Snapshot{}, apperr.New(apperr.KindValidation, "cli.analysis.snapshot", fmt.Sprintf("invalid snapshot %q", state.result.Config.Snapshot), err)
		}
		return value, nil
	}
	collect := dependencies.CollectSnapshot
	if collect == nil {
		collect = app.CollectLiveSnapshot
	}
	bounded, cancel := context.WithTimeout(ctx, state.result.Config.Timeout)
	defer cancel()
	value, err := collect(bounded, state.result.Config, dependencies.Version.Version)
	if err != nil {
		return snapshot.Snapshot{}, apperr.Wrap("cli.analysis.collect", err)
	}
	return value, nil
}

func actionFromArgs(verb, resourceArgument, apiGroup, namespace, resourceName string) (permission.Action, error) {
	verb = strings.ToLower(strings.TrimSpace(verb))
	resourceArgument = strings.TrimSpace(resourceArgument)
	if verb == "" || resourceArgument == "" {
		return permission.Action{}, fmt.Errorf("verb and resource cannot be empty")
	}
	if strings.HasPrefix(resourceArgument, "/") {
		if apiGroup != "" || resourceName != "" {
			return permission.Action{}, fmt.Errorf("--api-group and --resource-name cannot be used with a non-resource URL")
		}
		return permission.Action{Verb: verb, NonResourceURL: resourceArgument}, nil
	}
	resource, parsedGroup, subresource := permission.ParseResourceArgument(resourceArgument, apiGroup)
	if resource == "" {
		return permission.Action{}, fmt.Errorf("resource cannot be empty")
	}
	return permission.Action{
		Verb: verb, APIGroup: parsedGroup, Resource: resource, Subresource: subresource,
		Namespace: namespace, ResourceName: resourceName,
	}, nil
}

func writePermissions(writer io.Writer, output string, result permission.Result) error {
	if output == "json" {
		return writePermissionJSON(writer, result)
	}
	if _, err := fmt.Fprintf(writer, "identity: %s\ncomplete: %t\ncapabilities: %d\nwarnings: %d\n", result.Identity.String(), result.Complete, len(result.Capabilities), len(result.Warnings)); err != nil {
		return outputError("permissions", err)
	}
	return writeCapabilities(writer, result.Capabilities, result.Warnings)
}

func writeWhoCan(writer io.Writer, output string, result permission.WhoCanResult) error {
	if output == "json" {
		return writePermissionJSON(writer, result)
	}
	if _, err := fmt.Fprintf(writer, "request: %s\ncomplete: %t\nsubjects: %d\nwarnings: %d\n", actionString(result.Action), result.Complete, len(result.Subjects), len(result.Warnings)); err != nil {
		return outputError("who-can", err)
	}
	for _, subject := range result.Subjects {
		grants := grantCount(subject.Capabilities)
		if _, err := fmt.Fprintf(writer, "- %s (%d capabilities, %d grants)\n", subject.Identity.String(), len(subject.Capabilities), grants); err != nil {
			return outputError("who-can", err)
		}
		if err := writeCapabilities(writer, subject.Capabilities, nil); err != nil {
			return err
		}
	}
	return writeWarnings(writer, result.Warnings)
}

func writeWhyCan(writer io.Writer, output string, result permission.WhyCanResult) error {
	if output == "json" {
		return writePermissionJSON(writer, result)
	}
	if _, err := fmt.Fprintf(writer, "identity: %s\nrequest: %s\nallowed: %t\ncomplete: %t\nmatching capabilities: %d\nwarnings: %d\n", result.Identity.String(), actionString(result.Action), result.Allowed, result.Complete, len(result.Capabilities), len(result.Warnings)); err != nil {
		return outputError("why-can", err)
	}
	return writeCapabilities(writer, result.Capabilities, result.Warnings)
}

func writeCapabilities(writer io.Writer, capabilities []permission.Capability, warnings []permission.Warning) error {
	for _, capability := range capabilities {
		if _, err := fmt.Fprintf(writer, "- %s (%s; %d grants)\n", capabilityString(capability), scopeString(capability), len(capability.Grants)); err != nil {
			return outputError("permissions", err)
		}
		for _, grant := range capability.Grants {
			if _, err := fmt.Fprintf(writer, "  binding: %s %s -> %s %s; subject: %s; rule: %s\n", grant.BindingRef.Kind, qualifiedRef(grant.BindingRef), grant.RoleRef.Kind, qualifiedRef(grant.RoleRef), permission.Identity{Kind: grant.Subject.Kind, Namespace: grant.Subject.Namespace, Name: grant.Subject.Name}.String(), grant.PolicyRuleID); err != nil {
				return outputError("permissions", err)
			}
			if len(grant.AggregationChain) > 0 {
				parts := make([]string, 0, len(grant.AggregationChain))
				for _, ref := range grant.AggregationChain {
					parts = append(parts, qualifiedRef(ref))
				}
				if _, err := fmt.Fprintf(writer, "  aggregation: %s; source: %s\n", strings.Join(parts, " -> "), qualifiedRef(grant.SourceRoleRef)); err != nil {
					return outputError("permissions", err)
				}
			}
		}
	}
	return writeWarnings(writer, warnings)
}

func writeWarnings(writer io.Writer, warnings []permission.Warning) error {
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(writer, "warning: %s: %s\n", warning.Code, warning.Message); err != nil {
			return outputError("permissions", err)
		}
	}
	return nil
}

func writePermissionJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return outputError("permissions", err)
	}
	return nil
}

func capabilityString(value permission.Capability) string {
	if value.NonResourceURL != "" {
		return value.Verb + " " + value.NonResourceURL
	}
	resource := value.Resource
	if value.APIGroup != "" {
		resource += "." + value.APIGroup
	}
	if value.Subresource != "" {
		resource += "/" + value.Subresource
	}
	if len(value.ResourceNames) > 0 {
		resource += " names=" + strings.Join(value.ResourceNames, ",")
	}
	return value.Verb + " " + resource
}

func scopeString(value permission.Capability) string {
	if value.Namespace != "" {
		return string(value.Scope) + " namespace=" + value.Namespace
	}
	return string(value.Scope)
}

func actionString(value permission.Action) string {
	if value.NonResourceURL != "" {
		return value.Verb + " " + value.NonResourceURL
	}
	capability := permission.Capability{Verb: value.Verb, APIGroup: value.APIGroup, Resource: value.Resource, Subresource: value.Subresource}
	result := capabilityString(capability)
	if value.Namespace != "" {
		result += " namespace=" + value.Namespace
	}
	if value.ResourceName != "" {
		result += " name=" + value.ResourceName
	}
	return result
}

func grantCount(values []permission.Capability) int {
	count := 0
	for _, value := range values {
		count += len(value.Grants)
	}
	return count
}

func qualifiedRef(ref snapshot.ObjectRef) string {
	if ref.Namespace == "" {
		return ref.Name
	}
	return ref.Namespace + "/" + ref.Name
}

func outputError(operation string, err error) error {
	return apperr.New(apperr.KindOperational, "cli."+operation+".output", "cannot write permission output", err)
}
