package tui

import (
	"fmt"
	"strings"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/remediation"
)

func findingItems(data Dataset) []item {
	values := make([]item, 0, len(data.Findings.Findings))
	for _, finding := range data.Findings.Findings {
		namespace := findingNamespace(finding)
		values = append(values, item{
			ID: finding.ID, Title: finding.Title, Subtitle: fmt.Sprintf("%s · %d/100 · %s", finding.Severity, finding.RiskScore, finding.RuleID),
			Namespace: namespace, Severity: string(finding.Severity), Confidence: string(finding.Confidence), Risk: finding.RiskScore,
			Search: strings.ToLower(finding.Title + " " + finding.ID + " " + finding.RuleID + " " + namespace),
			Detail: findingDetail(finding), Evidence: findingEvidence(finding), Remediation: strings.Join(finding.Recommendations, "\n\n"),
		})
	}
	return values
}

func pathItems(data Dataset) []item {
	if data.Paths.SchemaVersion == "" {
		return pathSummaryItems(data)
	}
	riskByPath := make(map[string]int, len(data.Risk.PathScores))
	severityByPath := make(map[string]string, len(data.Risk.PathScores))
	for _, score := range data.Risk.PathScores {
		riskByPath[score.PathID], severityByPath[score.PathID] = score.Score, string(score.Severity)
	}
	values := make([]item, 0, len(data.Paths.Paths))
	for _, path := range data.Paths.Paths {
		riskValue, severity := riskByPath[path.ID], severityByPath[path.ID]
		values = append(values, item{
			ID: path.ID, Title: path.Title, Subtitle: fmt.Sprintf("risk %d %s · %s · cost %d", riskValue, defaultText(severity, "INFO"), path.Confidence, path.Cost),
			Namespace: path.Target.Namespace, Severity: severity, Confidence: string(path.Confidence), Risk: riskValue,
			Search: strings.ToLower(path.Title + " " + path.Source.String() + " " + string(path.Target.Type) + " " + path.Target.Namespace + " " + path.ID),
			Detail: pathDetail(path, riskValue, severity), Evidence: pathEvidence(path), Remediation: pathRemediation(path),
		})
	}
	return values
}

func pathSummaryItems(data Dataset) []item {
	values := make([]item, 0, len(data.Risk.PathScores))
	for _, score := range data.Risk.PathScores {
		namespace := score.Target.Namespace
		values = append(values, item{
			ID: score.PathID, Title: score.Title,
			Subtitle:  fmt.Sprintf("risk %d %s · %s · details on demand", score.Score, score.Severity, score.Confidence),
			Namespace: namespace, Severity: string(score.Severity), Confidence: string(score.Confidence), Risk: score.Score,
			Search: strings.ToLower(score.Title + " " + score.Source.String() + " " + string(score.Target.Type) + " " + namespace + " " + score.PathID),
			Detail: lines("ATTACK PATH SUMMARY", score.Title, fmt.Sprintf("Path ID: %s", score.PathID), fmt.Sprintf("Template: %s", score.TemplateID),
				fmt.Sprintf("Risk: %d/100 %s", score.Score, score.Severity), fmt.Sprintf("Confidence: %s · blocked %t", score.Confidence, score.Blocked),
				fmt.Sprintf("Source: %s", score.Source.String()), fmt.Sprintf("Target: %s", score.Target.Type), fmt.Sprintf("Namespace: %s", defaultText(namespace, "cluster-wide")),
				"", "Detailed steps and RBAC evidence are loaded only when this screen is requested."),
			Evidence: "Detailed path evidence is loading on demand.",
		})
	}
	return values
}

func warningItems(data Dataset) []item {
	values := make([]item, 0, len(data.Snapshot.Warnings)+len(data.Findings.Warnings)+len(data.Paths.Warnings)+len(data.Risk.Warnings))
	for _, warning := range data.Snapshot.Warnings {
		title := warning.Code + ": " + warning.Resource
		values = append(values, item{ID: "collection:" + title, Title: title, Subtitle: "COLLECTION", Severity: "HIGH", Search: strings.ToLower(title + " " + warning.Message), Detail: lines("COLLECTION WARNING", title, warning.Message)})
	}
	for _, warning := range data.Findings.Warnings {
		values = append(values, analysisWarningItem("findings", warning.Code, warning.Message))
	}
	for _, warning := range data.Paths.Warnings {
		values = append(values, analysisWarningItem("attack-path", warning.Code, warning.Message))
	}
	for _, warning := range data.Risk.Warnings {
		values = append(values, analysisWarningItem("risk", warning.Code, warning.Message))
	}
	if (data.Paths.SchemaVersion != "" && data.Paths.Truncated) || data.Risk.Truncated {
		values = append(values, item{ID: "analysis:truncated", Title: "BOUNDED_RESULT: analysis truncated", Subtitle: "ANALYSIS", Severity: "MEDIUM", Detail: "The configured expansion or path limit was reached. Results remain valid but are not exhaustive."})
	}
	return deduplicateItems(values)
}

func analysisWarningItem(source, code, message string) item {
	title := code + ": " + source
	return item{ID: source + ":" + code + ":" + message, Title: title, Subtitle: "ANALYSIS", Severity: "MEDIUM", Search: strings.ToLower(title + " " + message), Detail: lines("ANALYSIS WARNING", title, message)}
}

func findingNamespace(value analysis.Finding) string {
	for _, object := range value.AffectedObjects {
		if object.Namespace != "" {
			return object.Namespace
		}
	}
	for _, identity := range value.AffectedIdentities {
		if identity.Namespace != "" {
			return identity.Namespace
		}
	}
	return ""
}

func findingDetail(value analysis.Finding) string {
	parts := []string{"FINDING", value.Title, fmt.Sprintf("ID: %s", value.ID), fmt.Sprintf("Rule: %s", value.RuleID),
		fmt.Sprintf("Severity: %s · score %d/100", value.Severity, value.RiskScore), fmt.Sprintf("Confidence: %s", value.Confidence), "", value.Description, "", "SECURITY IMPACT", value.SecurityImpact}
	if len(value.Preconditions) > 0 {
		parts = append(parts, "", "PRECONDITIONS", bulletLines(value.Preconditions))
	}
	if len(value.MitigatingControls) > 0 {
		parts = append(parts, "", "OBSERVED MITIGATIONS", bulletLines(value.MitigatingControls))
	}
	return strings.Join(parts, "\n")
}

func findingEvidence(value analysis.Finding) string {
	parts := []string{fmt.Sprintf("Evidence records: %d", len(value.Evidence))}
	for _, evidence := range value.Evidence {
		switch {
		case evidence.Grant != nil:
			parts = append(parts, fmt.Sprintf("GRANT %s\n  %s %s -> %s %s\n  rule %s", evidence.Grant.ID, evidence.Grant.BindingRef.Kind, qualified(evidence.Grant.BindingRef), evidence.Grant.RoleRef.Kind, qualified(evidence.Grant.RoleRef), evidence.Grant.PolicyRuleID))
		case evidence.Ref != nil:
			parts = append(parts, fmt.Sprintf("OBJECT %s %s\n  %s = %s", evidence.Ref.Kind, qualified(*evidence.Ref), evidence.Field, evidence.Value))
		case evidence.Permission != nil:
			parts = append(parts, fmt.Sprintf("PERMISSION %s %s/%s scope=%s namespace=%s", evidence.Permission.Verb, evidence.Permission.Resource, evidence.Permission.Subresource, evidence.Permission.Scope, evidence.Permission.Namespace))
		}
	}
	return strings.Join(parts, "\n\n")
}

func pathDetail(value attackpath.Path, riskValue int, severity string) string {
	parts := []string{"ATTACK PATH", value.Title, fmt.Sprintf("ID: %s", value.ID), fmt.Sprintf("Template: %s", value.TemplateID),
		fmt.Sprintf("Risk: %d/100 %s", riskValue, defaultText(severity, "INFO")), fmt.Sprintf("Confidence: %s · blocked %t", value.Confidence, value.Blocked),
		fmt.Sprintf("Source: %s", value.Source.String()), fmt.Sprintf("Target: %s", value.Target.Type), fmt.Sprintf("Namespace: %s", defaultText(value.Target.Namespace, "cluster-wide")), fmt.Sprintf("Cost: %d", value.Cost)}
	if len(value.ConfidenceReasons) > 0 {
		parts = append(parts, "", "CONFIDENCE", bulletLines(value.ConfidenceReasons))
	}
	for index, step := range value.Steps {
		parts = append(parts, "", fmt.Sprintf("STEP %d · %s", index+1, step.TechniqueID), step.Description, fmt.Sprintf("%s → %s", step.From.Key, step.To.Key))
		for _, prerequisite := range step.Prerequisites {
			parts = append(parts, fmt.Sprintf("[%s] %s", prerequisite.State, prerequisite.Description))
		}
	}
	return strings.Join(parts, "\n")
}

func pathEvidence(value attackpath.Path) string {
	parts := make([]string, 0)
	for index, step := range value.Steps {
		parts = append(parts, fmt.Sprintf("STEP %d · %s", index+1, step.TechniqueID))
		for _, evidence := range step.Evidence {
			if evidence.Permission != nil {
				parts = append(parts, fmt.Sprintf("permission: %s %s/%s scope=%s namespace=%s", evidence.Permission.Verb, evidence.Permission.Resource, evidence.Permission.Subresource, evidence.Permission.Scope, evidence.Permission.Namespace))
			}
			if evidence.Grant != nil {
				parts = append(parts, fmt.Sprintf("grant: %s via %s %s -> %s %s", evidence.Grant.ID, evidence.Grant.BindingRef.Kind, qualified(evidence.Grant.BindingRef), evidence.Grant.RoleRef.Kind, qualified(evidence.Grant.RoleRef)))
			}
			if evidence.Ref != nil {
				parts = append(parts, fmt.Sprintf("object: %s %s %s=%s", evidence.Ref.Kind, qualified(*evidence.Ref), evidence.Field, evidence.Value))
			}
		}
		for _, control := range step.MitigatingControls {
			parts = append(parts, fmt.Sprintf("control: [%s] %s — %s", control.State, control.ControlType, control.Reason))
		}
		parts = append(parts, "")
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func pathRemediation(value attackpath.Path) string {
	var values []string
	for _, step := range value.Steps {
		values = append(values, step.RemediationCandidates...)
	}
	values = uniqueStrings(values)
	if len(values) == 0 {
		return "No advisory remediation candidate was produced for this path."
	}
	return bulletLines(values)
}

func remediationPanel(data Dataset, selectedID string) string {
	if data.Remediation.SchemaVersion == "" {
		return "No simulated remediation result is available."
	}
	values := make([]remediation.Candidate, 0)
	for _, candidate := range data.Remediation.Candidates {
		if candidate.Disposition != remediation.DispositionRecommended {
			continue
		}
		if containsString(candidate.PathIDs, selectedID) {
			values = append(values, candidate)
		}
	}
	if len(values) == 0 {
		for _, candidate := range data.Remediation.Candidates {
			if candidate.Disposition == remediation.DispositionRecommended {
				values = append(values, candidate)
			}
			if len(values) == 3 {
				break
			}
		}
	}
	if len(values) == 0 {
		return fmt.Sprintf("No recommendation produced.\nEvaluated: %d · ineffective: %d · dominated: %d", data.Remediation.Summary.Evaluated, data.Remediation.Summary.Ineffective, data.Remediation.Summary.Dominated)
	}
	parts := []string{fmt.Sprintf("Baseline cluster risk: %d %s", data.Remediation.BaselineRisk.Score, data.Remediation.BaselineRisk.Severity)}
	for index, candidate := range values {
		if index == 5 {
			break
		}
		parts = append(parts, "", fmt.Sprintf("#%d %s", candidate.Ranking.Rank, candidate.Title),
			fmt.Sprintf("%s · %s/%s", candidate.Kind, candidate.Change.Ref.Namespace, candidate.Change.Ref.Name),
			fmt.Sprintf("Risk %d → %d · benefit %d · cost %d", candidate.Impact.Risk.Cluster.Before, candidate.Impact.Risk.Cluster.After, candidate.Benefit.Total, candidate.Cost.Total),
			fmt.Sprintf("Paths removed %d · blocked %d · permissions lost %d", len(candidate.Impact.RemovedPathIDs), len(candidate.Impact.BlockedPathIDs), len(candidate.Impact.LostCapabilities)), candidate.Reason)
	}
	parts = append(parts, "", "Advisory only: no cluster changes were applied.")
	return strings.Join(parts, "\n")
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func deduplicateItems(values []item) []item {
	seen := make(map[string]struct{}, len(values))
	result := make([]item, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value.ID]; ok {
			continue
		}
		seen[value.ID] = struct{}{}
		result = append(result, value)
	}
	return result
}
