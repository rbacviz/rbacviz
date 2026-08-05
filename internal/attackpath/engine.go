package attackpath

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	defaultTop         = 10
	defaultMaxExpanded = 50000
)

// Engine evaluates built-in techniques over one immutable canonical snapshot.
type Engine struct {
	input    snapshot.Snapshot
	resolver *permission.Resolver
}

// New validates and indexes attack-path input.
func New(input snapshot.Snapshot) (*Engine, error) {
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return nil, fmt.Errorf("canonicalize attack-path input: %w", err)
	}
	resolver, err := permission.New(canonical)
	if err != nil {
		return nil, fmt.Errorf("initialize attack-path permissions: %w", err)
	}
	return &Engine{input: canonical, resolver: resolver}, nil
}

// Analyze returns ranked paths matching the bounded query.
func (engine *Engine) Analyze(ctx context.Context, query Query) (Result, error) {
	query = normalizeQuery(query)
	warnings := engine.initialWarnings()
	paths := make([]Path, 0, smallerInt(query.Top*2, query.MaxExpanded))
	expanded := 0
	truncated := false

	emit := func(candidate candidate) bool {
		if !candidateMatches(candidate, query) {
			return true
		}
		if expanded >= query.MaxExpanded {
			truncated = true
			return false
		}
		expanded++
		paths = append(paths, engine.materialize(candidate))
		return true
	}

	for _, candidate := range engine.directBindingCandidates() {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if !emit(candidate) {
			break
		}
	}
	if !truncated {
		for _, identity := range engine.input.Identities {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			source := permission.Identity{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name}
			if query.From != nil && identityKey(source) != identityKey(*query.From) {
				continue
			}
			resolved := engine.resolver.Permissions(source, nil)
			warnings = appendPermissionWarnings(warnings, resolved.Warnings)
			for _, candidate := range engine.capabilityCandidates(source, resolved.Capabilities) {
				if !emit(candidate) {
					break
				}
			}
			if truncated {
				break
			}
		}
	}

	paths = canonicalPaths(paths)
	if len(paths) > query.Top {
		paths = paths[:query.Top]
		truncated = true
	}
	warnings = canonicalWarnings(warnings)
	return Result{
		SchemaVersion: ResultSchemaVersion, TemplateSetVersion: TemplateSetVersion,
		Complete: engine.input.Metadata.Complete && len(warnings) == 0,
		Paths:    paths, Expanded: expanded, Truncated: truncated, Warnings: warnings,
	}, nil
}

func normalizeQuery(value Query) Query {
	if value.Top <= 0 {
		value.Top = defaultTop
	}
	if value.MaxExpanded <= 0 {
		value.MaxExpanded = defaultMaxExpanded
	}
	value.Namespace = strings.TrimSpace(value.Namespace)
	return value
}

func candidateMatches(value candidate, query Query) bool {
	if query.From != nil && identityKey(value.source) != identityKey(*query.From) {
		return false
	}
	if query.To != nil && value.target.Type != *query.To {
		return false
	}
	if query.Namespace == "" {
		return true
	}
	return value.target.Namespace == query.Namespace || value.source.Namespace == query.Namespace || value.scopeNamespace == query.Namespace
}

func (engine *Engine) initialWarnings() []Warning {
	result := make([]Warning, 0, len(engine.input.Warnings)+1)
	for _, warning := range engine.input.Warnings {
		result = append(result, Warning{Code: "Collection." + warning.Code, Message: warning.Resource + ": " + warning.Message})
	}
	if !engine.input.Metadata.Complete && len(engine.input.Warnings) == 0 {
		result = append(result, Warning{Code: "Collection.Incomplete", Message: "snapshot metadata marks collection incomplete"})
	}
	return result
}

func appendPermissionWarnings(target []Warning, values []permission.Warning) []Warning {
	for _, value := range values {
		ref := value.Ref
		var optional *snapshot.ObjectRef
		if ref.Kind != "" || ref.Name != "" {
			optional = &ref
		}
		target = append(target, Warning{Code: value.Code, Message: value.Message, Ref: optional})
	}
	return target
}

type candidate struct {
	metadata       TemplateMetadata
	source         permission.Identity
	target         PrivilegeTarget
	capability     *permission.Capability
	grant          *permission.GrantEvidence
	object         *snapshot.ObjectRef
	objectField    string
	objectValue    string
	prerequisites  []Prerequisite
	controls       []MitigationObservation
	baseConfidence Confidence
	reasons        []string
	scopeNamespace string
}

func (engine *Engine) directBindingCandidates() []candidate {
	result := make([]candidate, 0)
	for _, binding := range engine.input.Bindings {
		for _, subject := range binding.Subjects {
			source := permission.Identity{Kind: subject.Kind, Namespace: subject.Namespace, Name: subject.Name}
			if binding.Ref.Kind == "ClusterRoleBinding" && binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin" {
				result = append(result, bindingCandidate(templateByID("RBACVIZ-AP001"), source, binding, TargetClusterAdmin, ""))
			}
			if subject.Kind == snapshot.IdentityGroup && subject.Name == "system:masters" {
				result = append(result, bindingCandidate(templateByID("RBACVIZ-AP002"), source, binding, TargetSystemMasters, ""))
			}
		}
	}
	return result
}

func bindingCandidate(metadata TemplateMetadata, source permission.Identity, binding snapshot.Binding, targetType PrivilegeTargetType, namespace string) candidate {
	ref := binding.Ref
	grant := permission.GrantEvidence{
		ID: binding.ID, BindingRef: binding.Ref, RoleRef: binding.RoleRef, SourceRoleRef: binding.RoleRef,
		Subject:          snapshot.Subject{Kind: source.Kind, Namespace: source.Namespace, Name: source.Name},
		OriginalRule:     snapshot.PolicyRule{Verbs: []string{}, APIGroups: []string{}, Resources: []string{}, ResourceNames: []string{}, NonResourceURLs: []string{}},
		AggregationChain: []snapshot.ObjectRef{},
	}
	return candidate{metadata: metadata, source: source, target: newTarget(metadata, targetType, namespace, ""), grant: &grant, object: &ref, objectField: "roleRef", objectValue: binding.RoleRef.Name, baseConfidence: ConfidenceConfirmed, scopeNamespace: binding.Ref.Namespace}
}

func (engine *Engine) capabilityCandidates(source permission.Identity, capabilities []permission.Capability) []candidate {
	result := make([]candidate, 0)
	for index := range capabilities {
		capability := capabilities[index]
		for grantIndex := range capability.Grants {
			grant := capability.Grants[grantIndex]
			result = append(result, engine.candidatesForGrant(source, capabilities, capability, grant)...)
		}
	}
	return result
}

func newTarget(metadata TemplateMetadata, targetType PrivilegeTargetType, namespace, qualifier string) PrivilegeTarget {
	key := "privilege-target:" + strings.ToLower(string(targetType))
	if namespace != "" {
		key += ":" + namespace
	}
	if qualifier != "" {
		key += ":" + qualifier
	}
	return PrivilegeTarget{Type: targetType, Key: key, Namespace: namespace, Description: metadata.Description, PrivilegeGain: metadata.PrivilegeGain, BlastRadius: metadata.BlastRadius}
}

func smallerInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func identityKey(value permission.Identity) string {
	return string(value.Kind) + "\x00" + value.Namespace + "\x00" + value.Name
}

func canonicalWarnings(values []Warning) []Warning {
	sort.Slice(values, func(i, j int) bool { return warningKey(values[i]) < warningKey(values[j]) })
	result := make([]Warning, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || warningKey(result[len(result)-1]) != warningKey(value) {
			result = append(result, value)
		}
	}
	return result
}

func warningKey(value Warning) string {
	ref := ""
	if value.Ref != nil {
		ref = value.Ref.APIGroup + "\x00" + value.Ref.Kind + "\x00" + value.Ref.Namespace + "\x00" + value.Ref.Name
	}
	return value.Code + "\x00" + value.Message + "\x00" + ref
}
