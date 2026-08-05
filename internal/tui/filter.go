package tui

import (
	"sort"
	"strings"
)

func filterAndSort(values []item, view View, query string, filter, ordering int) []item {
	query = strings.ToLower(strings.TrimSpace(query))
	result := make([]item, 0, len(values))
	for _, value := range values {
		haystack := strings.ToLower(strings.Join([]string{value.Title, value.Subtitle, value.Namespace, value.Severity, value.Confidence, value.Search}, " "))
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		if !passesFilter(value, view, filter) {
			continue
		}
		result = append(result, value)
	}
	sort.SliceStable(result, func(left, right int) bool {
		switch ordering {
		case 1:
			if result[left].Title != result[right].Title {
				return result[left].Title < result[right].Title
			}
		case 2:
			if result[left].Namespace != result[right].Namespace {
				return result[left].Namespace < result[right].Namespace
			}
		default:
			if result[left].Risk != result[right].Risk {
				return result[left].Risk > result[right].Risk
			}
		}
		return result[left].ID < result[right].ID
	})
	return result
}

func passesFilter(value item, view View, selected int) bool {
	if selected == 0 {
		return true
	}
	switch view {
	case ViewIdentities:
		if selected == 1 {
			return strings.Contains(value.Subtitle, "User")
		}
		return strings.Contains(value.Subtitle, "Group")
	case ViewServiceAccounts, ViewNamespaces:
		if selected == 1 {
			return value.Risk >= 70
		}
		return value.Risk >= 40
	case ViewRoles, ViewClusterRoles:
		return strings.Contains(value.Subtitle, "wildcard true")
	case ViewPermissions:
		if selected == 1 {
			return strings.Contains(value.Subtitle, "Cluster")
		}
		if selected == 2 {
			return strings.Contains(value.Subtitle, "Namespaced")
		}
		return strings.Contains(value.Title, "*")
	case ViewFindings:
		if selected == 1 {
			return value.Severity == "CRITICAL"
		}
		return value.Severity == "CRITICAL" || value.Severity == "HIGH"
	case ViewAttackPaths:
		if selected == 1 {
			return value.Confidence == "CONFIRMED" || value.Confidence == "LIKELY"
		}
		if selected == 2 {
			return value.Confidence == "CONFIRMED"
		}
		return value.Confidence == "BLOCKED"
	case ViewWarnings:
		if selected == 1 {
			return value.Subtitle == "COLLECTION"
		}
		return value.Subtitle == "ANALYSIS"
	default:
		return true
	}
}

func filterCount(view View) int {
	switch view {
	case ViewIdentities, ViewServiceAccounts, ViewNamespaces, ViewWarnings:
		return 3
	case ViewPermissions, ViewAttackPaths:
		return 4
	case ViewRoles, ViewClusterRoles:
		return 2
	case ViewFindings:
		return 3
	default:
		return 1
	}
}

func filterLabel(view View, selected int) string {
	labels := []string{"all"}
	switch view {
	case ViewIdentities:
		labels = []string{"all", "users", "groups"}
	case ViewServiceAccounts, ViewNamespaces:
		labels = []string{"all", "high+ risk", "medium+ risk"}
	case ViewRoles, ViewClusterRoles:
		labels = []string{"all", "wildcards"}
	case ViewPermissions:
		labels = []string{"all", "cluster", "namespaced", "wildcards"}
	case ViewFindings:
		labels = []string{"all", "critical", "high+"}
	case ViewAttackPaths:
		labels = []string{"all", "actionable", "confirmed", "blocked"}
	case ViewWarnings:
		labels = []string{"all", "collection", "analysis"}
	}
	if selected < 0 || selected >= len(labels) {
		return labels[0]
	}
	return labels[selected]
}

func sortCount(View) int { return 3 }

func sortLabel(_ View, selected int) string {
	labels := []string{"risk / source order", "title", "namespace"}
	if selected < 0 || selected >= len(labels) {
		return labels[0]
	}
	return labels[selected]
}
