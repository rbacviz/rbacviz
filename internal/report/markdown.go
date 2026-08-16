package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/rbacviz/rbacviz/internal/explain"
)

// WriteMarkdown renders a portable report without terminal color or control
// sequences. The same Result can be serialized as JSON by the CLI.
func WriteMarkdown(writer io.Writer, result Result) error {
	write := func(format string, arguments ...any) error {
		_, err := fmt.Fprintf(writer, format, arguments...)
		return err
	}
	if err := write("# RBACVIZ Kubernetes RBAC Security Report\n\n"); err != nil {
		return err
	}
	if err := write("> Risk Index is a posture indicator, not the probability that the cluster will be compromised.\n\n"); err != nil {
		return err
	}
	if err := write("## Executive summary\n\n"); err != nil {
		return err
	}
	if err := write("| Field | Value |\n|---|---:|\n"); err != nil {
		return err
	}
	rows := [][2]any{
		{"Snapshot collected", valueOrDash(result.SnapshotCollected)},
		{"Cluster context", valueOrDash(result.ClusterContext)},
		{"Namespace scope", valueOrDash(result.Namespace)},
		{"Analysis complete", result.Complete},
		{"Analysis truncated", result.Truncated},
		{"Risk Index", fmt.Sprintf("%d/100 (%s)", result.Summary.RiskIndex, result.Summary.RiskSeverity)},
		{"Risk model", result.Summary.RiskModelVersion},
		{"Risk families", result.Summary.RiskFamilies},
		{"Contributing risk families", result.Summary.ContributingRiskFamilies},
		{"Raw findings", result.Summary.RawFindings},
		{"Detected root causes", result.Summary.DetectedRootCauses},
		{"Unique root causes", result.Summary.RootCauses},
		{"Accepted exceptions", result.Summary.AcceptedExceptions},
		{"Expired exceptions", result.Summary.ExpiredExceptions},
		{"Unmatched exceptions", result.Summary.UnmatchedExceptions},
		{"Attack paths", result.Summary.AttackPaths},
		{"Actionable paths", result.Summary.ActionablePaths},
		{"Conditional paths", result.Summary.ConditionalPaths},
		{"Blocked paths", result.Summary.BlockedPaths},
		{"Recommended fixes", result.Summary.RecommendedFixes},
	}
	for _, row := range rows {
		if err := write("| %v | %v |\n", row[0], row[1]); err != nil {
			return err
		}
	}
	if result.Baseline != nil {
		if err := write("\nBaseline `%s` evaluated at `%s` using profile `%s` (%d entries).\n", result.Baseline.SchemaVersion, result.Baseline.EvaluatedAt, result.Baseline.Profile, result.Baseline.Entries); err != nil {
			return err
		}
	}
	if result.Summary.OmittedIssues > 0 {
		if err := write("\n> The report includes the top %d root causes; %d lower-priority root causes were omitted by the output bound.\n", result.Summary.IncludedIssues, result.Summary.OmittedIssues); err != nil {
			return err
		}
	}

	if err := write("\n## Priority remediation plan\n\n"); err != nil {
		return err
	}
	if err := write("| Priority | Root cause | Status | Severity | Risk | Proposed fixes |\n|---|---|---|---|---:|---:|\n"); err != nil {
		return err
	}
	for _, issue := range result.Issues {
		if err := write("| %s | %s | %s | %s | %d | %d |\n", issue.Priority, escapeCell(issue.Title), issue.Actionability, issue.Severity, issue.MaxPathRisk, len(issue.Fixes)); err != nil {
			return err
		}
	}

	if err := write("\n## Detailed root causes\n"); err != nil {
		return err
	}
	for index, issue := range result.Issues {
		if err := write("\n### %d. [%s] %s\n\n", index+1, issue.Priority, issue.Title); err != nil {
			return err
		}
		if err := write("- **Issue ID:** `%s`\n- **Severity:** %s\n- **Actionability:** %s\n- **Confidence:** %s\n- **Maximum path risk:** %d/100\n- **Correlated signals:** %d findings, %d rules, %d attack paths\n\n", issue.ID, issue.Severity, issue.Actionability, issue.Confidence, issue.MaxPathRisk, len(issue.FindingIDs), len(issue.RuleIDs), len(issue.PathIDs)); err != nil {
			return err
		}
		if err := write("**Root cause**\n\n%s\n\n", issue.RootCause); err != nil {
			return err
		}
		if issue.SecurityImpact != "" {
			if err := write("**Why it matters**\n\n%s\n\n", issue.SecurityImpact); err != nil {
				return err
			}
		}
		if len(issue.AffectedIdentities) > 0 {
			if err := write("**Affected identities**\n\n"); err != nil {
				return err
			}
			for _, identity := range issue.AffectedIdentities {
				if err := write("- `%s`\n", identity.String()); err != nil {
					return err
				}
			}
			if err := write("\n"); err != nil {
				return err
			}
		}
		if len(issue.AccessExplanations) > 0 {
			if err := write("**Access chain**\n\n"); err != nil {
				return err
			}
			for _, access := range issue.AccessExplanations {
				if err := write("```text\n%s\n```\n\n", explain.RenderTree(access)); err != nil {
					return err
				}
			}
		}
		if len(issue.Evidence) > 0 {
			if err := write("**Evidence**\n\n"); err != nil {
				return err
			}
			for _, evidence := range issue.Evidence {
				if err := write("- %s\n", evidence); err != nil {
					return err
				}
			}
			if err := write("\n"); err != nil {
				return err
			}
		}
		if len(issue.Recommendations) > 0 {
			if err := write("**General recommendations**\n\n"); err != nil {
				return err
			}
			for _, recommendation := range issue.Recommendations {
				if err := write("- %s\n", recommendation); err != nil {
					return err
				}
			}
			if err := write("\n"); err != nil {
				return err
			}
		}
		if len(issue.Fixes) == 0 {
			if err := write("**Validated remediation candidate:** none. Review the evidence manually; RBACVIZ does not guess an unmeasured change.\n"); err != nil {
				return err
			}
			continue
		}
		if err := write("**Virtually evaluated fixes**\n"); err != nil {
			return err
		}
		for fixIndex, fix := range issue.Fixes {
			if err := write("\n%d. **%s** (`%s`)\n\n", fixIndex+1, fix.Title, fix.Kind); err != nil {
				return err
			}
			if err := write("   - Object: `%s %s`\n   - Simulated cluster risk: %d → %d (%+d)\n   - Paths removed: %d; blocked: %d; remaining: %d\n   - Effective capabilities lost: %d\n   - Reason: %s\n", fix.Change.Ref.Kind, displayRef(fix.Change.Ref), fix.RiskBefore, fix.RiskAfter, fix.RiskDelta, fix.RemovedPaths, fix.BlockedPaths, fix.RemainingPaths, fix.LostCapabilities, fix.Reason); err != nil {
				return err
			}
			if fix.Change.Before != "" || fix.Change.After != "" {
				if err := write("   - Change: `%s` → `%s`\n", valueOrDash(fix.Change.Before), valueOrDash(fix.Change.After)); err != nil {
					return err
				}
			}
			if len(fix.Verification) > 0 {
				if err := write("\n   Verification after the change:\n\n"); err != nil {
					return err
				}
				for _, command := range fix.Verification {
					if err := write("   ```bash\n   %s\n   ```\n", command); err != nil {
						return err
					}
				}
			}
			if err := write("\n   > %s\n", fix.Caution); err != nil {
				return err
			}
		}
	}

	if len(result.AcceptedExceptions) > 0 {
		if err := write("\n## Accepted exceptions\n\nAccepted exceptions remain visible with their evidence and review metadata. Only entries selecting an exact risk family or root cause are excluded from the active Risk Index until expiry; rule-only entries affect the matching finding only.\n\n"); err != nil {
			return err
		}
		for _, exception := range result.AcceptedExceptions {
			if err := writeException(write, exception); err != nil {
				return err
			}
		}
	}
	if len(result.ExpiredExceptions) > 0 {
		if err := write("\n## Expired exceptions\n\nThese entries were not applied and their matching issues remain active.\n\n"); err != nil {
			return err
		}
		for _, exception := range result.ExpiredExceptions {
			if err := writeException(write, exception); err != nil {
				return err
			}
		}
	}
	if len(result.UnmatchedExceptions) > 0 {
		if err := write("\n## Unmatched baseline entries\n\nThese non-expired entries matched no current finding or risk family and should be reviewed for staleness.\n\n"); err != nil {
			return err
		}
		for _, exception := range result.UnmatchedExceptions {
			if err := writeException(write, exception); err != nil {
				return err
			}
		}
	}

	if len(result.Warnings) > 0 {
		if err := write("\n## Analysis limitations\n\n"); err != nil {
			return err
		}
		for _, warning := range result.Warnings {
			if err := write("- **%s/%s:** %s\n", warning.Source, warning.Code, warning.Message); err != nil {
				return err
			}
		}
	}
	if err := write("\n## Safety note\n\nThis report is advisory. RBACVIZ did not apply any change to the cluster and did not read Secret values. Every listed fix must be reviewed and tested before application.\n"); err != nil {
		return err
	}
	return nil
}

func writeException(write func(string, ...any) error, value Exception) error {
	suppression := value.Suppression
	if err := write("### [%s] %s\n\n", value.State, suppression.ID); err != nil {
		return err
	}
	if err := write("- **Owner:** %s\n- **Reason:** %s\n- **Expires:** %s\n", suppression.Owner, suppression.Reason, suppression.Expires); err != nil {
		return err
	}
	if suppression.Ticket != "" {
		if err := write("- **Ticket:** %s\n", suppression.Ticket); err != nil {
			return err
		}
	}
	if err := write("- **Selector:** rule=`%s`, subject=`%s`, namespace=`%s`, riskFamilyId=`%s`, rootCauseKey=`%s`\n- **Matched signals:** %d findings, %d risk families, %d root causes\n",
		valueOrDash(suppression.Rule), valueOrDash(suppression.Subject), valueOrDash(suppression.Namespace),
		valueOrDash(suppression.RiskFamilyID), valueOrDash(suppression.RootCauseKey),
		len(value.FindingIDs), len(value.RiskFamilyIDs), len(value.RootCauseKeys)); err != nil {
		return err
	}
	if suppression.Binding != nil {
		name := suppression.Binding.Name
		if suppression.Binding.Namespace != "" {
			name = suppression.Binding.Namespace + "/" + name
		}
		if err := write("- **Binding:** `%s %s`\n", suppression.Binding.Kind, name); err != nil {
			return err
		}
	}
	for _, issue := range value.Issues {
		if err := write("\nCorrelated issue `%s`: **%s** (%s, maximum path risk %d/100)\n\n", issue.ID, issue.Title, issue.Severity, issue.MaxPathRisk); err != nil {
			return err
		}
		if err := write("- Root cause: %s\n", issue.RootCause); err != nil {
			return err
		}
		for _, evidence := range issue.Evidence {
			if err := write("- Evidence: %s\n", evidence); err != nil {
				return err
			}
		}
	}
	return write("\n")
}

func escapeCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
