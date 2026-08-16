package explain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/permission"
)

// RenderTree produces a portable, no-color access tree suitable for the TUI,
// Markdown code blocks, and plain-text output.
func RenderTree(value AccessExplanation) string {
	parts := make([]string, 0)
	for index, workload := range value.Workloads {
		if index == 3 {
			parts = append(parts, fmt.Sprintf("… %d more workloads", len(value.Workloads)-index))
			break
		}
		parts = append(parts, workload.Kind+" "+displayRef(workload), "   │ RUNS_AS", "   ▼")
	}
	parts = append(parts, string(value.Subject.Kind)+" "+identityName(value.Subject), "   │ BOUND_BY", "   ▼",
		value.Binding.Kind+" "+displayRef(value.Binding), "   │ GRANTS", "   ▼", value.Role.Kind+" "+displayRef(value.Role))
	if len(value.AggregationChain) > 0 {
		parts = append(parts, "   │ AGGREGATES")
		for _, ref := range value.AggregationChain {
			parts = append(parts, "   ├── "+ref.Kind+" "+displayRef(ref))
		}
	}
	parts = append(parts, "   │ "+scopeLabel(value), "   ▼")
	capabilities := groupedCapabilities(value.Capabilities)
	for index, capability := range capabilities {
		branch := "├──"
		if index == len(capabilities)-1 {
			branch = "└──"
		}
		parts = append(parts, branch+" "+capability)
	}
	if len(capabilities) == 0 {
		parts = append(parts, "└── no effective capabilities resolved")
	}
	return strings.Join(parts, "\n")
}

// RenderAnalysis produces the compact analytical conclusion displayed below
// an access tree. It contains no terminal color or control sequences.
func RenderAnalysis(value AccessExplanation) string {
	analysisValue := value.Analysis
	parts := []string{
		"ANALYSIS",
		fmt.Sprintf("Priority: %s · Status: %s", analysisValue.Priority, analysisValue.Status),
		fmt.Sprintf("Severity: %s · Confidence: %s", analysisValue.Severity, analysisValue.Confidence),
	}
	if analysisValue.MaxPathRisk > 0 {
		parts = append(parts, fmt.Sprintf("Maximum path risk: %d/100", analysisValue.MaxPathRisk))
	}
	parts = append(parts, "", "Root cause:", analysisValue.RootCause, "", "Why flagged:", analysisValue.Impact)
	if len(analysisValue.Recommendations) > 0 {
		parts = append(parts, "", "Suggested fix:", "• "+strings.Join(analysisValue.Recommendations, "\n• "))
	}
	if len(analysisValue.Verification) > 0 {
		parts = append(parts, "", "Verify:", analysisValue.Verification[0])
	}
	if len(value.FindingIDs) > 0 || len(value.PathIDs) > 0 {
		parts = append(parts, "", fmt.Sprintf("Signals: %d findings · %d paths", len(value.FindingIDs), len(value.PathIDs)))
	}
	return strings.Join(parts, "\n")
}

func groupedCapabilities(values []CapabilitySummary) []string {
	type group struct {
		verbs      []string
		resource   string
		severity   analysis.Severity
		confidence string
		risk       int
	}
	groups := make(map[string]*group)
	for _, value := range values {
		resource := capabilityResource(value)
		key := strings.Join([]string{resource, string(value.Scope), value.Namespace, strings.Join(value.ResourceNames, ","), string(value.Severity), string(value.Confidence)}, "|")
		current, ok := groups[key]
		if !ok {
			current = &group{resource: resource, severity: analysis.SeverityInfo, confidence: string(value.Confidence)}
			groups[key] = current
		}
		current.verbs = appendUnique(current.verbs, value.Verb)
		if severityRank(value.Severity) > severityRank(current.severity) {
			current.severity = value.Severity
			current.confidence = string(value.Confidence)
		}
		if value.Risk > current.risk {
			current.risk = value.Risk
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		value := groups[key]
		sort.Strings(value.verbs)
		line := strings.Join(value.verbs, "/") + " " + value.resource
		if value.severity != analysis.SeverityInfo {
			line += fmt.Sprintf(" [%s · %s]", value.severity, value.confidence)
		}
		result = append(result, line)
	}
	return result
}

func capabilityResource(value CapabilitySummary) string {
	if value.NonResourceURL != "" {
		return value.NonResourceURL
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
	return resource
}

func identityName(value permission.Identity) string {
	if value.Namespace == "" {
		return value.Name
	}
	return value.Namespace + "/" + value.Name
}

func scopeLabel(value AccessExplanation) string {
	if value.Binding.Kind == "RoleBinding" {
		return "effective scope: namespace " + value.Binding.Namespace
	}
	hasCluster, hasNamespaced, hasNonResource, hasUnknown := false, false, false, false
	for _, capability := range value.Capabilities {
		switch capability.Scope {
		case permission.ScopeCluster:
			hasCluster = true
		case permission.ScopeNamespaced:
			hasNamespaced = true
		case permission.ScopeNonResource:
			hasNonResource = true
		default:
			hasUnknown = true
		}
	}
	values := make([]string, 0, 4)
	if hasCluster {
		values = append(values, "cluster resources")
	}
	if hasNamespaced {
		values = append(values, "all namespaces")
	}
	if hasNonResource {
		values = append(values, "API paths")
	}
	if hasUnknown {
		values = append(values, "unknown scope")
	}
	if len(values) == 0 {
		return "effective scope: no resolved access"
	}
	return "effective scope: " + strings.Join(values, ", ")
}
