package tui

import (
	"fmt"
	"strings"

	"github.com/rbacviz/rbacviz/internal/explain"
	"github.com/rbacviz/rbacviz/internal/permission"
)

func accessContent(values []explain.AccessExplanation) string {
	if len(values) == 0 {
		return "No effective RBAC grant chain is associated with this item.\n\nSelect an identity, ServiceAccount, role, permission, finding, or attack path to inspect its access provenance."
	}
	parts := make([]string, 0)
	limit := len(values)
	if limit > 3 {
		limit = 3
	}
	for index := 0; index < limit; index++ {
		value := values[index]
		if len(values) > 1 {
			parts = append(parts, fmt.Sprintf("CHAIN %d OF %d", index+1, len(values)))
		}
		parts = append(parts, explain.RenderTree(value), "", explain.RenderAnalysis(value))
		if index+1 < limit {
			parts = append(parts, "", strings.Repeat("─", 24), "")
		}
	}
	if len(values) > limit {
		parts = append(parts, "", fmt.Sprintf("… %d additional independent grant chains", len(values)-limit), "Open Evidence or the report for the complete set.")
	}
	return strings.Join(parts, "\n")
}

func explanationGrantCount(values []explain.AccessExplanation, selected permission.Capability) int {
	seen := make(map[string]struct{})
	for _, value := range values {
		for _, capability := range value.Capabilities {
			if !sameAccessCapability(capability, selected) {
				continue
			}
			for _, grantID := range capability.GrantIDs {
				seen[grantID] = struct{}{}
			}
		}
	}
	return len(seen)
}

func explanationEvidence(values []explain.AccessExplanation, selected permission.Capability) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		grantIDs := make([]string, 0)
		for _, capability := range value.Capabilities {
			if sameAccessCapability(capability, selected) {
				grantIDs = append(grantIDs, capability.GrantIDs...)
			}
		}
		if len(grantIDs) == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s\nBinding: %s %s\nRole: %s %s\nGrants: %s", value.Subject.String(), value.Binding.Kind, qualified(value.Binding), value.Role.Kind, qualified(value.Role), strings.Join(uniqueStrings(grantIDs), ", ")))
	}
	return strings.Join(parts, "\n\n")
}

func sameAccessCapability(left explain.CapabilitySummary, right permission.Capability) bool {
	return left.Verb == right.Verb && left.APIGroup == right.APIGroup && left.Resource == right.Resource && left.Subresource == right.Subresource && left.NonResourceURL == right.NonResourceURL && left.Scope == right.Scope && left.Namespace == right.Namespace && strings.Join(left.ResourceNames, "\x00") == strings.Join(right.ResourceNames, "\x00")
}
