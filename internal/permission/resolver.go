package permission

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// Resolver is an immutable, indexed view of one canonical snapshot.
type Resolver struct {
	snapshot       snapshot.Snapshot
	roles          map[string]snapshot.Role
	effectiveRules map[string][]ruleOrigin
	bindings       []snapshot.Binding
	apiResources   map[string]snapshot.APIResource
	warnings       []Warning
}

// New validates and indexes a snapshot and computes aggregated ClusterRoles.
func New(input snapshot.Snapshot) (*Resolver, error) {
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return nil, fmt.Errorf("canonicalize permission input: %w", err)
	}
	resolver := &Resolver{
		snapshot: canonical, roles: make(map[string]snapshot.Role, len(canonical.Roles)),
		effectiveRules: make(map[string][]ruleOrigin, len(canonical.Roles)),
		bindings:       append([]snapshot.Binding(nil), canonical.Bindings...),
		apiResources:   make(map[string]snapshot.APIResource, len(canonical.APIResources)),
	}
	for _, role := range canonical.Roles {
		resolver.roles[refKey(role.Ref)] = role
	}
	for _, resource := range canonical.APIResources {
		resolver.apiResources[resourceKey(resource.APIGroup, resource.Name)] = resource
	}
	for _, warning := range canonical.Warnings {
		resolver.addWarning(Warning{Code: "Collection." + warning.Code, Message: warning.Resource + ": " + warning.Message})
	}
	resolver.buildAggregates()
	resolver.validateRoleReferences()
	return resolver, nil
}

// Permissions returns all capabilities granted directly to identity and, for
// a User query, to only the explicitly supplied groups.
func (resolver *Resolver) Permissions(identity Identity, groups []string) Result {
	groups = canonicalGroups(groups)
	wanted := map[string]struct{}{subjectKey(subjectFromIdentity(identity)): {}}
	if identity.Kind == snapshot.IdentityUser {
		for _, group := range groups {
			wanted[subjectKey(snapshot.Subject{Kind: snapshot.IdentityGroup, Name: group})] = struct{}{}
		}
	} else {
		groups = []string{}
	}

	capabilities := make(map[string]*Capability)
	warnings := append([]Warning(nil), resolver.warnings...)
	for _, binding := range resolver.bindings {
		matched := make([]snapshot.Subject, 0, len(binding.Subjects))
		for _, subject := range binding.Subjects {
			if _, ok := wanted[subjectKey(subject)]; ok {
				matched = append(matched, subject)
			}
		}
		if len(matched) == 0 {
			continue
		}
		roleKey := refKey(binding.RoleRef)
		role, found := resolver.roles[roleKey]
		if !found {
			continue
		}
		for _, origin := range resolver.effectiveRules[roleKey] {
			for _, subject := range matched {
				for _, capability := range resolver.normalizeRule(binding, role, subject, origin, &warnings) {
					key := capabilityKey(capability)
					current, ok := capabilities[key]
					if !ok {
						capabilityCopy := capability
						capabilityCopy.Grants = []GrantEvidence{}
						current = &capabilityCopy
						capabilities[key] = current
					}
					for _, grant := range capability.Grants {
						appendUniqueGrant(&current.Grants, grant)
					}
				}
			}
		}
	}
	result := make([]Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		sort.Slice(capability.Grants, func(i, j int) bool { return capability.Grants[i].ID < capability.Grants[j].ID })
		result = append(result, *capability)
	}
	sort.Slice(result, func(i, j int) bool { return capabilityKey(result[i]) < capabilityKey(result[j]) })
	warnings = canonicalWarnings(warnings)
	return Result{
		SchemaVersion: ResultSchemaVersion, Complete: resolver.snapshot.Metadata.Complete && len(warnings) == 0,
		Identity: identity, Groups: groups, Capabilities: result, Warnings: warnings,
	}
}

// WhoCan returns every directly represented subject that matches action. It
// intentionally does not expand Group subjects into unknown users.
func (resolver *Resolver) WhoCan(action Action) WhoCanResult {
	identities := make(map[string]Identity)
	for _, binding := range resolver.bindings {
		for _, subject := range binding.Subjects {
			identity := identityFromSubject(subject)
			identities[identityKey(identity)] = identity
		}
	}
	keys := sortedMapKeys(identities)
	matches := make([]SubjectMatch, 0)
	warnings := append([]Warning(nil), resolver.warnings...)
	for _, key := range keys {
		identity := identities[key]
		permissions := resolver.Permissions(identity, nil)
		warnings = append(warnings, permissions.Warnings...)
		capabilities := matchingCapabilities(permissions.Capabilities, action)
		if len(capabilities) > 0 {
			matches = append(matches, SubjectMatch{Identity: identity, Capabilities: capabilities})
		}
	}
	warnings = canonicalWarnings(warnings)
	return WhoCanResult{
		SchemaVersion: ResultSchemaVersion, Complete: resolver.snapshot.Metadata.Complete && len(warnings) == 0,
		Action: action, Subjects: matches, Warnings: warnings,
	}
}

// WhyCan explains every independent grant matching identity and action.
func (resolver *Resolver) WhyCan(identity Identity, groups []string, action Action) WhyCanResult {
	permissions := resolver.Permissions(identity, groups)
	matches := matchingCapabilities(permissions.Capabilities, action)
	return WhyCanResult{
		SchemaVersion: ResultSchemaVersion, Complete: permissions.Complete, Identity: identity,
		Groups: permissions.Groups, Action: action, Allowed: len(matches) > 0,
		Capabilities: matches, Warnings: permissions.Warnings,
	}
}

func (resolver *Resolver) normalizeRule(binding snapshot.Binding, role snapshot.Role, subject snapshot.Subject, origin ruleOrigin, warnings *[]Warning) []Capability {
	result := make([]Capability, 0)
	roleBinding := binding.Ref.Kind == "RoleBinding"
	for _, verb := range origin.rule.Verbs {
		for _, apiGroup := range origin.rule.APIGroups {
			for _, resourceSelector := range origin.rule.Resources {
				resource, subresource := splitResource(resourceSelector)
				scope, known := resolver.resourceScope(apiGroup, resourceSelector)
				if !known && resource != "*" {
					*warnings = append(*warnings, Warning{
						Code: "UnknownResourceScope", Message: fmt.Sprintf("scope is unknown for %s/%s", displayAPIGroup(apiGroup), resourceSelector), Ref: role.Ref,
					})
				}
				if roleBinding {
					if known && scope == ScopeCluster {
						continue
					}
					scope = ScopeNamespaced
				}
				namespace := ""
				if scope == ScopeNamespaced {
					if roleBinding {
						namespace = binding.Ref.Namespace
					} else {
						namespace = "*"
					}
				}
				capability := Capability{
					Verb: verb, APIGroup: apiGroup, Resource: resource, Subresource: subresource,
					ResourceNames: append([]string(nil), origin.rule.ResourceNames...), Scope: scope, Namespace: namespace,
				}
				capability.Grants = []GrantEvidence{newGrant(binding, role, subject, origin)}
				result = append(result, capability)
			}
		}
		if !roleBinding {
			for _, url := range origin.rule.NonResourceURLs {
				capability := Capability{Verb: verb, NonResourceURL: url, Scope: ScopeNonResource, ResourceNames: []string{}}
				capability.Grants = []GrantEvidence{newGrant(binding, role, subject, origin)}
				result = append(result, capability)
			}
		}
	}
	return result
}

func (resolver *Resolver) resourceScope(apiGroup, selector string) (Scope, bool) {
	if selector == "*" || strings.HasPrefix(selector, "*/") {
		return ScopeUnknown, false
	}
	resource := resolver.apiResources[resourceKey(apiGroup, selector)]
	if resource.Name == "" {
		base, _ := splitResource(selector)
		resource = resolver.apiResources[resourceKey(apiGroup, base)]
	}
	if resource.Name == "" {
		return ScopeUnknown, false
	}
	if resource.Namespaced {
		return ScopeNamespaced, true
	}
	return ScopeCluster, true
}

func (resolver *Resolver) validateRoleReferences() {
	for _, binding := range resolver.bindings {
		if _, found := resolver.roles[refKey(binding.RoleRef)]; !found {
			resolver.addWarning(Warning{
				Code:    "MissingRoleReference",
				Message: fmt.Sprintf("%s %s references missing %s %s", binding.Ref.Kind, qualifiedName(binding.Ref), binding.RoleRef.Kind, qualifiedName(binding.RoleRef)),
				Ref:     binding.Ref,
			})
		}
	}
}

func newGrant(binding snapshot.Binding, role snapshot.Role, subject snapshot.Subject, origin ruleOrigin) GrantEvidence {
	key := strings.Join([]string{binding.ID, subjectKey(subject), role.ID, origin.rule.ID, refKey(origin.source), refsKey(origin.chain)}, "\x00")
	digest := sha256.Sum256([]byte(key))
	return GrantEvidence{
		ID: "grant-" + hex.EncodeToString(digest[:12]), PolicyRuleID: origin.rule.ID,
		BindingRef: binding.Ref, RoleRef: role.Ref, SourceRoleRef: origin.source, Subject: subject,
		OriginalRule: origin.rule, AggregationChain: append([]snapshot.ObjectRef(nil), origin.chain...),
	}
}

func matchingCapabilities(values []Capability, action Action) []Capability {
	result := make([]Capability, 0)
	for _, capability := range values {
		if Allows(capability, action) {
			result = append(result, capability)
		}
	}
	return result
}

func appendUniqueGrant(values *[]GrantEvidence, candidate GrantEvidence) {
	for _, existing := range *values {
		if existing.ID == candidate.ID {
			return
		}
	}
	*values = append(*values, candidate)
}

func (resolver *Resolver) addWarning(value Warning) {
	resolver.warnings = canonicalWarnings(append(resolver.warnings, value))
}

func canonicalWarnings(values []Warning) []Warning {
	sort.Slice(values, func(i, j int) bool { return warningKey(values[i]) < warningKey(values[j]) })
	if len(values) == 0 {
		return []Warning{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if warningKey(values[read]) != warningKey(values[write-1]) {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}

func warningKey(value Warning) string {
	return value.Code + "|" + value.Message + "|" + refKey(value.Ref)
}
func capabilityKey(value Capability) string {
	return strings.Join([]string{string(value.Scope), value.Namespace, value.APIGroup, value.Resource, value.Subresource, value.Verb, strings.Join(value.ResourceNames, ","), value.NonResourceURL}, "\x00")
}
func resourceKey(apiGroup, resource string) string { return apiGroup + "\x00" + resource }
func refKey(ref snapshot.ObjectRef) string {
	return strings.Join([]string{ref.APIGroup, ref.Kind, ref.Namespace, ref.Name}, "\x00")
}
func refsKey(refs []snapshot.ObjectRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, refKey(ref))
	}
	return strings.Join(parts, "\x01")
}
func sameRef(left, right snapshot.ObjectRef) bool { return refKey(left) == refKey(right) }
func qualifiedName(ref snapshot.ObjectRef) string {
	if ref.Namespace == "" {
		return ref.Name
	}
	return ref.Namespace + "/" + ref.Name
}
func splitResource(value string) (string, string) {
	resource, subresource, _ := strings.Cut(value, "/")
	return resource, subresource
}
func displayAPIGroup(value string) string {
	if value == "" {
		return "core"
	}
	return value
}
