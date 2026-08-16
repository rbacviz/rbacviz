package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/permission"
	reportmodel "github.com/rbacviz/rbacviz/internal/report"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	// ReportMappingVersion identifies the root-cause report to SARIF mapping.
	ReportMappingVersion   = "1.0.0"
	genericRootCauseRuleID = "RBACVIZ-ROOT-CAUSE"
)

type reportDocument struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []reportRun `json:"runs"`
}

type reportRun struct {
	Tool        reportTool         `json:"tool"`
	Results     []reportResult     `json:"results"`
	Invocations []reportInvocation `json:"invocations,omitempty"`
	Properties  reportRunProperty  `json:"properties"`
}

type reportTool struct {
	Driver reportDriver `json:"driver"`
}

type reportDriver struct {
	Name           string                         `json:"name"`
	InformationURI string                         `json:"informationUri"`
	Version        string                         `json:"version,omitempty"`
	Rules          []reportRuleDescriptor         `json:"rules"`
	Notifications  []reportNotificationDescriptor `json:"notifications,omitempty"`
}

type reportRuleDescriptor struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription message              `json:"shortDescription"`
	FullDescription  message              `json:"fullDescription"`
	Properties       reportRuleProperties `json:"properties"`
}

type reportRuleProperties struct {
	SecuritySeverity string   `json:"security-severity"`
	Severity         string   `json:"severity"`
	Tags             []string `json:"tags"`
}

type reportResult struct {
	RuleID              string               `json:"ruleId"`
	Level               string               `json:"level"`
	Kind                string               `json:"kind"`
	Message             message              `json:"message"`
	Locations           []location           `json:"locations,omitempty"`
	PartialFingerprints map[string]string    `json:"partialFingerprints"`
	Suppressions        []reportSuppression  `json:"suppressions,omitempty"`
	Properties          reportResultProperty `json:"properties"`
}

type reportSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type reportSuppressionProperty struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Owner   string `json:"owner"`
	Expires string `json:"expires"`
	Ticket  string `json:"ticket,omitempty"`
}

type reportResultProperty struct {
	Issue                reportmodel.Issue           `json:"reportIssue"`
	AcceptedSuppressions []reportSuppressionProperty `json:"acceptedSuppressions,omitempty"`
	ExpiredSuppressions  []reportSuppressionProperty `json:"expiredSuppressions,omitempty"`
	PartiallyAccepted    bool                        `json:"partiallyAccepted"`
	FullyAccepted        bool                        `json:"fullyAccepted"`
}

type reportRunProperty struct {
	ReportSchemaVersion string                       `json:"reportSchemaVersion"`
	ReportModelVersion  string                       `json:"reportModelVersion"`
	SARIFMappingVersion string                       `json:"sarifMappingVersion"`
	ToolVersion         string                       `json:"toolVersion,omitempty"`
	Complete            bool                         `json:"complete"`
	Truncated           bool                         `json:"truncated"`
	SnapshotCollectedAt string                       `json:"snapshotCollectedAt,omitempty"`
	ClusterContext      string                       `json:"clusterContext,omitempty"`
	ClusterFingerprint  string                       `json:"clusterFingerprint,omitempty"`
	Namespace           string                       `json:"namespace,omitempty"`
	Inventory           reportmodel.Inventory        `json:"inventory"`
	Summary             reportmodel.Summary          `json:"summary"`
	Baseline            *reportmodel.BaselineSummary `json:"baseline,omitempty"`
	Warnings            []reportmodel.Warning        `json:"warnings"`
}

type reportInvocation struct {
	ExecutionSuccessful        bool                 `json:"executionSuccessful"`
	ToolExecutionNotifications []reportNotification `json:"toolExecutionNotifications,omitempty"`
}

type reportNotification struct {
	Level      string                     `json:"level"`
	Message    message                    `json:"message"`
	Descriptor reportDescriptorReference  `json:"descriptor"`
	Properties reportNotificationProperty `json:"properties"`
}

type reportNotificationDescriptor struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	ShortDescription message `json:"shortDescription"`
}

type reportDescriptorReference struct {
	ID string `json:"id"`
}

type reportNotificationProperty struct {
	Source string `json:"source"`
}

type issueResultBuilder struct {
	issue    reportmodel.Issue
	order    int
	active   bool
	accepted []reportSuppressionProperty
	expired  []reportSuppressionProperty
}

type ruleBuilder struct {
	id       string
	title    string
	severity analysis.Severity
	risk     int
}

// WriteReport serializes the stable root-cause report contract as SARIF 2.1.0.
// It performs no analysis of its own and never contacts or mutates a cluster.
func WriteReport(writer io.Writer, value reportmodel.Result) error {
	builders := reportIssueBuilders(value)
	rules := reportRules(builders)
	notificationRules := reportNotificationRules(value.Warnings)
	results := make([]reportResult, 0, len(builders))
	for _, builder := range builders {
		results = append(results, resultFromIssue(builder))
	}

	notifications := make([]reportNotification, 0, len(value.Warnings))
	for _, warning := range value.Warnings {
		notifications = append(notifications, reportNotification{
			Level: "warning", Message: message{Text: warning.Message},
			Descriptor: reportDescriptorReference{ID: notificationID(warning.Code)},
			Properties: reportNotificationProperty{Source: warning.Source},
		})
	}

	payload := reportDocument{Version: "2.1.0", Schema: schemaURI, Runs: []reportRun{{
		Tool: reportTool{Driver: reportDriver{
			Name: "rbacviz", InformationURI: "https://github.com/rbacviz/rbacviz",
			Version: value.ToolVersion, Rules: rules, Notifications: notificationRules,
		}},
		Results: results,
		Invocations: []reportInvocation{{
			ExecutionSuccessful: true, ToolExecutionNotifications: notifications,
		}},
		Properties: reportRunProperty{
			ReportSchemaVersion: value.SchemaVersion, ReportModelVersion: value.ModelVersion,
			SARIFMappingVersion: ReportMappingVersion,
			ToolVersion:         value.ToolVersion, Complete: value.Complete, Truncated: value.Truncated,
			SnapshotCollectedAt: value.SnapshotCollected, ClusterContext: value.ClusterContext,
			ClusterFingerprint: value.ClusterFingerprint, Namespace: value.Namespace,
			Inventory: value.Inventory, Summary: value.Summary, Baseline: value.Baseline,
			Warnings: value.Warnings,
		},
	}}}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func reportIssueBuilders(value reportmodel.Result) []issueResultBuilder {
	byID := make(map[string]*issueResultBuilder)
	ordered := make([]*issueResultBuilder, 0, len(value.Issues))
	add := func(issue reportmodel.Issue, active bool) *issueResultBuilder {
		if existing, found := byID[issue.ID]; found {
			if active {
				existing.issue = issue
				existing.active = true
			}
			return existing
		}
		builder := &issueResultBuilder{issue: issue, order: len(ordered), active: active}
		byID[issue.ID] = builder
		ordered = append(ordered, builder)
		return builder
	}
	for _, issue := range value.Issues {
		add(issue, true)
	}
	for _, exception := range value.AcceptedExceptions {
		metadata := suppressionProperty(exception.Suppression)
		for _, issue := range exception.Issues {
			builder := add(issue, false)
			builder.accepted = appendSuppression(builder.accepted, metadata)
		}
	}
	for _, exception := range value.ExpiredExceptions {
		metadata := suppressionProperty(exception.Suppression)
		for _, issue := range exception.Issues {
			if builder, found := byID[issue.ID]; found {
				builder.expired = appendSuppression(builder.expired, metadata)
			}
		}
	}
	result := make([]issueResultBuilder, 0, len(ordered))
	for _, builder := range ordered {
		sortSuppressions(builder.accepted)
		sortSuppressions(builder.expired)
		result = append(result, *builder)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].active != result[j].active {
			return result[i].active
		}
		return result[i].order < result[j].order
	})
	return result
}

func resultFromIssue(builder issueResultBuilder) reportResult {
	issue := builder.issue
	fullyAccepted := !builder.active && len(builder.accepted) > 0
	partiallyAccepted := builder.active && len(builder.accepted) > 0
	result := reportResult{
		RuleID: primaryRuleID(issue), Level: reportLevel(issue, fullyAccepted), Kind: "fail",
		Message: message{Text: reportMessage(issue)}, Locations: reportLocations(issue),
		PartialFingerprints: map[string]string{
			"rbacvizIssueId/v1":   issue.ID,
			"rbacvizRootCause/v1": rootCauseFingerprint(issue.RootCauseKey),
		},
		Properties: reportResultProperty{
			Issue: issue, AcceptedSuppressions: builder.accepted, ExpiredSuppressions: builder.expired,
			PartiallyAccepted: partiallyAccepted, FullyAccepted: fullyAccepted,
		},
	}
	if fullyAccepted {
		result.Kind = "review"
		result.Suppressions = make([]reportSuppression, 0, len(builder.accepted))
		for _, suppression := range builder.accepted {
			result.Suppressions = append(result.Suppressions, reportSuppression{
				Kind: "external", Status: "accepted", Justification: suppressionJustification(suppression),
			})
		}
	}
	return result
}

func reportRules(builders []issueResultBuilder) []reportRuleDescriptor {
	byID := make(map[string]*ruleBuilder)
	for _, builder := range builders {
		issue := builder.issue
		id := primaryRuleID(issue)
		candidate := issue.MaxPathRisk
		if candidate == 0 {
			candidate = severityRisk(issue.Severity)
		}
		current, found := byID[id]
		if !found {
			byID[id] = &ruleBuilder{id: id, title: issue.Title, severity: issue.Severity, risk: candidate}
			continue
		}
		if issue.Title != "" && (current.title == "" || issue.Title < current.title) {
			current.title = issue.Title
		}
		if candidate > current.risk {
			current.risk = candidate
			current.severity = issue.Severity
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]reportRuleDescriptor, 0, len(ids))
	for _, id := range ids {
		builder := byID[id]
		title := builder.title
		if title == "" {
			title = "Kubernetes RBAC root cause"
		}
		result = append(result, reportRuleDescriptor{
			ID: id, Name: sarifName(id), ShortDescription: message{Text: title},
			FullDescription: message{Text: "A root-cause-oriented Kubernetes RBAC security issue correlated by the rbacviz report model."},
			Properties: reportRuleProperties{
				SecuritySeverity: fmt.Sprintf("%.1f", float64(builder.risk)/10),
				Severity:         strings.ToLower(string(builder.severity)),
				Tags:             []string{"security", "kubernetes", "rbac", "rbacviz"},
			},
		})
	}
	return result
}

func reportNotificationRules(warnings []reportmodel.Warning) []reportNotificationDescriptor {
	byID := make(map[string]string)
	for _, warning := range warnings {
		id := notificationID(warning.Code)
		if current, found := byID[id]; !found || warning.Message < current {
			byID[id] = warning.Message
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]reportNotificationDescriptor, 0, len(ids))
	for _, id := range ids {
		result = append(result, reportNotificationDescriptor{
			ID: id, Name: sarifName(id), ShortDescription: message{Text: byID[id]},
		})
	}
	return result
}

func notificationID(code string) string {
	if strings.TrimSpace(code) == "" {
		return "RBACVIZ-WARNING"
	}
	return code
}

func primaryRuleID(issue reportmodel.Issue) string {
	if len(issue.RuleIDs) == 0 {
		return genericRootCauseRuleID
	}
	rules := append([]string(nil), issue.RuleIDs...)
	sort.Strings(rules)
	return rules[0]
}

func reportLevel(issue reportmodel.Issue, accepted bool) string {
	if accepted || issue.Actionability == reportmodel.ActionabilityBlocked || issue.Priority == reportmodel.PriorityP3 {
		return "note"
	}
	switch issue.Priority {
	case reportmodel.PriorityP0, reportmodel.PriorityP1:
		return "error"
	case reportmodel.PriorityP2:
		return "warning"
	default:
		return sarifLevel(issue.Severity)
	}
}

func reportMessage(issue reportmodel.Issue) string {
	parts := []string{fmt.Sprintf("[%s %s] %s", issue.Priority, issue.Actionability, issue.Title)}
	if issue.RootCause != "" {
		parts = append(parts, "Root cause: "+issue.RootCause)
	}
	if issue.SecurityImpact != "" {
		parts = append(parts, "Impact: "+issue.SecurityImpact)
	}
	return strings.Join(parts, ". ")
}

func reportLocations(issue reportmodel.Issue) []location {
	objects := rootCauseObjects(issue)
	byURI := make(map[string]location)
	logicals := reportLogicalLocations(issue.AffectedIdentities)
	for _, ref := range objects {
		uri := kubernetesURI(ref)
		byURI[uri] = location{
			PhysicalLocation: &physicalLocation{ArtifactLocation: artifactLocation{URI: uri}},
			LogicalLocations: logicals,
		}
	}
	values := make([]string, 0, len(byURI))
	for uri := range byURI {
		values = append(values, uri)
	}
	sort.Strings(values)
	result := make([]location, 0, len(values))
	for _, uri := range values {
		result = append(result, byURI[uri])
	}
	if len(result) == 0 && len(logicals) > 0 {
		result = append(result, location{LogicalLocations: logicals})
	}
	return result
}

func rootCauseObjects(issue reportmodel.Issue) []snapshot.ObjectRef {
	byURI := make(map[string]snapshot.ObjectRef)
	for _, explanation := range issue.AccessExplanations {
		ref := explanation.Binding
		byURI[kubernetesURI(ref)] = ref
	}
	if len(byURI) == 0 && len(issue.AffectedObjects) > 0 {
		ref := issue.AffectedObjects[0]
		byURI[kubernetesURI(ref)] = ref
	}
	values := make([]string, 0, len(byURI))
	for uri := range byURI {
		values = append(values, uri)
	}
	sort.Strings(values)
	result := make([]snapshot.ObjectRef, 0, len(values))
	for _, uri := range values {
		result = append(result, byURI[uri])
	}
	return result
}

func reportLogicalLocations(identities []permission.Identity) []logicalLocation {
	values := make([]string, 0, len(identities))
	seen := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		name := identity.String()
		if _, found := seen[name]; found {
			continue
		}
		seen[name] = struct{}{}
		values = append(values, name)
	}
	sort.Strings(values)
	result := make([]logicalLocation, 0, len(values))
	for _, value := range values {
		result = append(result, logicalLocation{Name: value, FullyQualifiedName: value, Kind: "object"})
	}
	return result
}

func suppressionProperty(value baseline.Suppression) reportSuppressionProperty {
	return reportSuppressionProperty{
		ID: value.ID, Reason: value.Reason, Owner: value.Owner,
		Expires: value.Expires, Ticket: value.Ticket,
	}
}

func appendSuppression(values []reportSuppressionProperty, value reportSuppressionProperty) []reportSuppressionProperty {
	for _, existing := range values {
		if existing.ID == value.ID {
			return values
		}
	}
	return append(values, value)
}

func sortSuppressions(values []reportSuppressionProperty) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}

func suppressionJustification(value reportSuppressionProperty) string {
	parts := []string{
		"suppression=" + value.ID, "owner=" + value.Owner,
		"expires=" + value.Expires, "reason=" + value.Reason,
	}
	if value.Ticket != "" {
		parts = append(parts, "ticket="+value.Ticket)
	}
	return strings.Join(parts, "; ")
}

func rootCauseFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func severityRisk(value analysis.Severity) int {
	switch value {
	case analysis.SeverityCritical:
		return 95
	case analysis.SeverityHigh:
		return 80
	case analysis.SeverityMedium:
		return 55
	case analysis.SeverityLow:
		return 25
	default:
		return 0
	}
}
