package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type capabilityPredicate func(permission.Capability) bool

type capabilityRule struct {
	metadata  RuleMetadata
	predicate capabilityPredicate
}

func (rule capabilityRule) Metadata() RuleMetadata { return rule.metadata }

func (rule capabilityRule) Evaluate(ctx context.Context, input EvaluationContext) ([]Finding, error) {
	result := make([]Finding, 0)
	for _, subject := range input.Subjects {
		for _, capability := range subject.Capabilities {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !rule.predicate(capability) {
				continue
			}
			result = append(result, permissionFinding(rule.metadata, subject.Identity, capability))
		}
	}
	return result, nil
}

func permissionFinding(metadata RuleMetadata, identity permission.Identity, capability permission.Capability) Finding {
	permissionValue := &PermissionEvidence{
		Verb: capability.Verb, APIGroup: capability.APIGroup, Resource: capability.Resource,
		Subresource: capability.Subresource, ResourceNames: append([]string(nil), capability.ResourceNames...),
		NonResourceURL: capability.NonResourceURL, Scope: capability.Scope, Namespace: capability.Namespace,
	}
	evidence := make([]Evidence, 0, len(capability.Grants))
	objects := make([]snapshot.ObjectRef, 0, len(capability.Grants)*3)
	for _, grant := range capability.Grants {
		grantCopy := grant
		permissionCopy := *permissionValue
		evidence = append(evidence, Evidence{Kind: "RBACGrant", Ref: refPointer(grant.BindingRef), Field: "roleRef", Permission: &permissionCopy, Grant: &grantCopy})
		objects = append(objects, grant.BindingRef, grant.RoleRef, grant.SourceRoleRef)
	}
	return Finding{
		Confidence:      ConfidenceConfirmed,
		Description:     fmt.Sprintf("%s: %s has %s.", metadata.Description, identityString(identity), capabilityString(capability)),
		AffectedObjects: objects, AffectedIdentities: []permission.Identity{identity}, Evidence: evidence,
		Preconditions: []string{}, MitigatingControls: []string{}, AttackPaths: []string{},
		fingerprint: identityKey(identity) + "\x00" + capabilityKey(capability),
	}
}

type bindingRule struct {
	metadata RuleMetadata
	match    func(snapshot.Binding, snapshot.Subject) bool
}

func (rule bindingRule) Metadata() RuleMetadata { return rule.metadata }

func (rule bindingRule) Evaluate(ctx context.Context, input EvaluationContext) ([]Finding, error) {
	result := make([]Finding, 0)
	for _, binding := range input.Snapshot.Bindings {
		for _, subject := range binding.Subjects {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !rule.match(binding, subject) {
				continue
			}
			identity := permission.Identity{Kind: subject.Kind, Namespace: subject.Namespace, Name: subject.Name}
			result = append(result, Finding{
				Confidence:         ConfidenceConfirmed,
				Description:        fmt.Sprintf("%s: %s is referenced by %s %s.", rule.metadata.Description, identityString(identity), binding.Ref.Kind, qualifiedRef(binding.Ref)),
				AffectedObjects:    []snapshot.ObjectRef{binding.Ref, binding.RoleRef},
				AffectedIdentities: []permission.Identity{identity},
				Evidence:           []Evidence{{Kind: "ObjectField", Ref: refPointer(binding.Ref), Field: "roleRef", Value: qualifiedRef(binding.RoleRef)}},
				Preconditions:      []string{}, MitigatingControls: []string{}, AttackPaths: []string{},
				fingerprint: objectKey(binding.Ref) + "\x00" + identityKey(identity),
			})
		}
	}
	return result, nil
}

func verbIs(values ...string) func(permission.Capability) bool {
	return func(value permission.Capability) bool {
		for _, candidate := range values {
			if value.Verb == "*" || strings.EqualFold(value.Verb, candidate) {
				return true
			}
		}
		return false
	}
}

func resourceIs(group, resource string) func(permission.Capability) bool {
	return func(value permission.Capability) bool {
		return (value.APIGroup == "*" || value.APIGroup == group) && (value.Resource == "*" || value.Resource == resource)
	}
}

func subresourceIs(group, resource, subresource string) func(permission.Capability) bool {
	return func(value permission.Capability) bool {
		if value.APIGroup != "*" && value.APIGroup != group {
			return false
		}
		if value.Resource == "*" && value.Subresource == "" {
			return true
		}
		return value.Resource == resource && (value.Subresource == subresource || value.Subresource == "*")
	}
}

func all(predicates ...capabilityPredicate) capabilityPredicate {
	return func(value permission.Capability) bool {
		for _, predicate := range predicates {
			if !predicate(value) {
				return false
			}
		}
		return true
	}
}

func capabilityKey(value permission.Capability) string {
	return strings.Join([]string{value.Verb, value.APIGroup, value.Resource, value.Subresource, strings.Join(value.ResourceNames, ","), value.NonResourceURL, string(value.Scope), value.Namespace}, "\x00")
}

func capabilityString(value permission.Capability) string {
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
	result := value.Verb + " " + target
	if value.Namespace != "" {
		result += " in namespace " + value.Namespace
	}
	return result
}

func identityString(value permission.Identity) string {
	switch value.Kind {
	case snapshot.IdentityServiceAccount:
		return "serviceaccount:" + value.Namespace + ":" + value.Name
	case snapshot.IdentityGroup:
		return "group:" + value.Name
	default:
		return "user:" + value.Name
	}
}

func qualifiedRef(value snapshot.ObjectRef) string {
	if value.Namespace == "" {
		return value.Name
	}
	return value.Namespace + "/" + value.Name
}

func refPointer(value snapshot.ObjectRef) *snapshot.ObjectRef {
	refCopy := value
	return &refCopy
}
