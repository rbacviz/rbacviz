package permission

import "strings"

// Allows reports whether a normalized capability matches an authorization
// action using Kubernetes RBAC wildcard, resourceName, subresource, scope, and
// non-resource URL semantics.
func Allows(capability Capability, action Action) bool {
	verb := strings.ToLower(action.Verb)
	if strings.ToLower(capability.Verb) != "*" && strings.ToLower(capability.Verb) != verb {
		return false
	}
	if action.NonResourceURL != "" {
		return capability.Scope == ScopeNonResource && nonResourceMatches(capability.NonResourceURL, action.NonResourceURL)
	}
	if capability.Scope == ScopeNonResource || capability.NonResourceURL != "" || action.Resource == "" {
		return false
	}
	if capability.APIGroup != "*" && capability.APIGroup != action.APIGroup {
		return false
	}
	if !resourceMatches(capability.Resource, capability.Subresource, action.Resource, action.Subresource) {
		return false
	}
	if capability.Scope == ScopeNamespaced && capability.Namespace != "" && capability.Namespace != "*" {
		// An empty request namespace is an intentional cross-namespace query.
		if action.Namespace != "" && capability.Namespace != action.Namespace {
			return false
		}
	}
	if len(capability.ResourceNames) > 0 {
		if action.ResourceName == "" {
			return false
		}
		for _, name := range capability.ResourceNames {
			if name == action.ResourceName {
				return true
			}
		}
		return false
	}
	return true
}

func resourceMatches(ruleResource, ruleSubresource, requestResource, requestSubresource string) bool {
	if ruleResource == "*" && ruleSubresource == "" {
		return true
	}
	if ruleResource != "*" && ruleResource != requestResource {
		return false
	}
	return ruleSubresource == requestSubresource
}

func nonResourceMatches(ruleURL, requestURL string) bool {
	if ruleURL == "*" {
		return true
	}
	if strings.HasSuffix(ruleURL, "*") {
		return strings.HasPrefix(requestURL, strings.TrimSuffix(ruleURL, "*"))
	}
	return ruleURL == requestURL
}

// ParseResourceArgument accepts resource, resource.group,
// resource/subresource, and resource.group/subresource.
func ParseResourceArgument(value, apiGroupOverride string) (resource, apiGroup, subresource string) {
	base, subresource, _ := strings.Cut(value, "/")
	resource = base
	apiGroup = apiGroupOverride
	if apiGroup == "" {
		if index := strings.IndexByte(base, '.'); index > 0 {
			resource = base[:index]
			apiGroup = base[index+1:]
		}
	}
	return resource, apiGroup, subresource
}
