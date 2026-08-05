package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func lines(values ...string) string { return strings.Join(values, "\n") }

func defaultText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func bulletLines(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, "• "+value)
	}
	return strings.Join(parts, "\n")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func qualified(ref snapshot.ObjectRef) string {
	if ref.Namespace != "" {
		return ref.Namespace + "/" + ref.Name
	}
	return ref.Name
}

func inventoryDetail(value snapshot.Snapshot) string {
	return lines("CLUSTER INVENTORY", fmt.Sprintf("API resources: %d", len(value.APIResources)),
		fmt.Sprintf("Identities: %d", len(value.Identities)), fmt.Sprintf("ServiceAccounts: %d", len(value.ServiceAccounts)),
		fmt.Sprintf("Roles: %d", len(value.Roles)), fmt.Sprintf("Bindings: %d", len(value.Bindings)),
		fmt.Sprintf("Workloads: %d", len(value.Workloads)), fmt.Sprintf("Assets: %d", len(value.Assets)),
		fmt.Sprintf("Security controls: %d", len(value.SecurityControls)))
}

func collectionDetail(value snapshot.Snapshot) string {
	parts := []string{"COLLECTION", fmt.Sprintf("Complete: %t", value.Metadata.Complete), fmt.Sprintf("Collected: %s", value.Metadata.CollectedAt),
		fmt.Sprintf("Context: %s", defaultText(value.Metadata.Context, "not persisted")), fmt.Sprintf("Scope: %s", collectionScope(value)), fmt.Sprintf("Warnings: %d", len(value.Warnings))}
	for _, warning := range value.Warnings {
		parts = append(parts, "", fmt.Sprintf("[%s] %s", warning.Code, warning.Resource), warning.Message)
	}
	return strings.Join(parts, "\n")
}

func collectionScope(value snapshot.Snapshot) string {
	if value.Metadata.AllNamespaces {
		return "all namespaces"
	}
	return defaultText(value.Metadata.Namespace, "current namespace")
}

func completionTitle(complete bool) string {
	if complete {
		return "Collection complete"
	}
	return "Collection incomplete"
}

func completionSeverity(complete bool) string {
	if complete {
		return "INFO"
	}
	return "HIGH"
}

func severityCounts(data Dataset) string {
	counts := map[string]int{}
	for _, value := range data.Findings.Findings {
		counts[string(value.Severity)]++
	}
	return fmt.Sprintf("%d critical · %d high · %d medium · %d low", counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
}

func roleHasWildcard(value snapshot.Role) bool {
	for _, rule := range value.Rules {
		if contains(rule.Verbs, "*") || contains(rule.APIGroups, "*") || contains(rule.Resources, "*") {
			return true
		}
	}
	return false
}

func roleDetail(value snapshot.Role) string {
	parts := []string{strings.ToUpper(value.Ref.Kind), qualified(value.Ref), fmt.Sprintf("Rules: %d", len(value.Rules)), fmt.Sprintf("Aggregation selectors: %d", len(value.AggregationSelectors))}
	for index, rule := range value.Rules {
		parts = append(parts, "", fmt.Sprintf("RULE %d · %s", index+1, rule.ID), "verbs: "+strings.Join(rule.Verbs, ", "), "apiGroups: "+strings.Join(rule.APIGroups, ", "), "resources: "+strings.Join(rule.Resources, ", "))
		if len(rule.ResourceNames) > 0 {
			parts = append(parts, "resourceNames: "+strings.Join(rule.ResourceNames, ", "))
		}
		if len(rule.NonResourceURLs) > 0 {
			parts = append(parts, "nonResourceURLs: "+strings.Join(rule.NonResourceURLs, ", "))
		}
	}
	return strings.Join(parts, "\n")
}

func roleEvidence(value snapshot.Role) string {
	parts := []string{fmt.Sprintf("Object: %s %s", value.Ref.Kind, qualified(value.Ref)), fmt.Sprintf("Stable ID: %s", value.ID)}
	for _, rule := range value.Rules {
		parts = append(parts, fmt.Sprintf("Rule %s\n  verbs=%s\n  groups=%s\n  resources=%s", rule.ID, strings.Join(rule.Verbs, ","), strings.Join(rule.APIGroups, ","), strings.Join(rule.Resources, ",")))
	}
	return strings.Join(parts, "\n\n")
}

func capabilityTitle(value permission.Capability) string {
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
	return value.Verb + " " + resource
}

func capabilityDetail(value permission.Capability) string {
	parts := []string{"EFFECTIVE PERMISSION", capabilityTitle(value), fmt.Sprintf("Scope: %s", value.Scope), fmt.Sprintf("Namespace: %s", defaultText(value.Namespace, "cluster-wide")), fmt.Sprintf("Independent grants: %d", len(value.Grants))}
	if len(value.ResourceNames) > 0 {
		parts = append(parts, "Resource names: "+strings.Join(value.ResourceNames, ", "))
	}
	return strings.Join(parts, "\n")
}

func capabilityEvidence(value permission.Capability) string {
	parts := make([]string, 0, len(value.Grants))
	for _, grant := range value.Grants {
		parts = append(parts, fmt.Sprintf("GRANT %s\nBinding: %s %s\nRole: %s %s\nRule: %s\nSubject: %s", grant.ID, grant.BindingRef.Kind, qualified(grant.BindingRef), grant.RoleRef.Kind, qualified(grant.RoleRef), grant.PolicyRuleID, permission.Identity{Kind: grant.Subject.Kind, Namespace: grant.Subject.Namespace, Name: grant.Subject.Name}.String()))
	}
	return strings.Join(parts, "\n\n")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	return string([]rune(value)[:width-1]) + "…"
}

func wrapText(value string, width int) string {
	if width < 4 {
		return value
	}
	var result []string
	for _, source := range strings.Split(value, "\n") {
		if utf8.RuneCountInString(source) <= width {
			result = append(result, source)
			continue
		}
		indent := ""
		trimmed := strings.TrimSpace(source)
		if strings.HasPrefix(trimmed, "• ") {
			indent = "  "
		}
		words, line := strings.Fields(source), ""
		for _, word := range words {
			if utf8.RuneCountInString(word) > width {
				word = truncate(word, width)
			}
			candidate := word
			if line != "" {
				candidate = line + " " + word
			}
			if utf8.RuneCountInString(candidate) > width {
				result = append(result, line)
				line = indent + word
			} else {
				line = candidate
			}
		}
		if line != "" {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}
