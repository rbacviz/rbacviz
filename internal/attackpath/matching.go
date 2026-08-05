package attackpath

import (
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
)

func capabilityMatches(value permission.Capability, verbs, groups, resources, subresources []string) bool {
	return fieldMatches(value.Verb, verbs) && fieldMatches(value.APIGroup, groups) && resourceMatches(value.Resource, value.Subresource, resources, subresources)
}

func resourceMatches(actualResource, actualSubresource string, resources, subresources []string) bool {
	if len(resources) == 0 {
		return fieldMatches(actualSubresource, subresources)
	}
	for _, resource := range resources {
		if actualResource != "*" && resource != "*" && !strings.EqualFold(actualResource, resource) {
			continue
		}
		if actualResource == "*" && actualSubresource == "" {
			return true
		}
		if fieldMatches(actualSubresource, subresources) {
			return true
		}
	}
	return false
}

func fieldMatches(actual string, wanted []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, value := range wanted {
		if actual == "*" || value == "*" || strings.EqualFold(actual, value) {
			return true
		}
	}
	return false
}

func hasCapability(values []permission.Capability, verbs, groups, resources, subresources []string) bool {
	for _, value := range values {
		if capabilityMatches(value, verbs, groups, resources, subresources) {
			return true
		}
	}
	return false
}

func capabilityNamespace(value permission.Capability, source permission.Identity) string {
	if value.Namespace != "" && value.Namespace != "*" {
		return value.Namespace
	}
	if value.Scope == permission.ScopeNamespaced && source.Namespace != "" {
		return source.Namespace
	}
	return ""
}

func addressesName(value permission.Capability, name string) bool {
	if len(value.ResourceNames) == 0 || name == "" {
		return true
	}
	for _, candidate := range value.ResourceNames {
		if candidate == name || candidate == "*" {
			return true
		}
	}
	return false
}
