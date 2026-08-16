package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/baseline"
	"github.com/rbacviz/rbacviz/internal/explain"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/remediation"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	defaultMaxIssues     = 50
	defaultMaxCandidates = 50
	defaultMaxPaths      = 10000
	defaultMaxExpanded   = 100000
)

// Build runs the existing analyzers and correlates their results into unique,
// prioritized root-cause issues. It never contacts or mutates a cluster.
func Build(ctx context.Context, input snapshot.Snapshot, options Options) (Result, error) {
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize report input: %w", err)
	}
	options = normalizeOptions(options)
	if options.Baseline != nil {
		if err := baseline.Validate(*options.Baseline); err != nil {
			return Result{}, fmt.Errorf("validate report baseline: %w", err)
		}
	}

	findingEngine, err := analysis.New(canonical)
	if err != nil {
		return Result{}, fmt.Errorf("initialize report findings: %w", err)
	}
	findings, err := findingEngine.Analyze(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("analyze report findings: %w", err)
	}
	if options.Namespace != "" {
		findings.Findings = filterFindingsByNamespace(findings.Findings, options.Namespace)
	}

	riskEngine, err := risk.New(canonical)
	if err != nil {
		return Result{}, fmt.Errorf("initialize report risk: %w", err)
	}
	risks, err := riskEngine.Analyze(ctx, risk.Query{
		Namespace: options.Namespace, MaxPaths: options.MaxPaths,
		MaxExpanded: options.MaxExpanded, IncludePath: true,
	})
	if err != nil {
		return Result{}, fmt.Errorf("analyze report risk: %w", err)
	}
	access, err := explain.Build(ctx, canonical, nil, findings, attackpath.Result{}, risks)
	if err != nil {
		return Result{}, fmt.Errorf("explain report access: %w", err)
	}

	remediations, err := remediation.Generate(ctx, canonical, remediation.Options{
		Namespace: options.Namespace, MaxCandidates: options.MaxCandidates,
		MaxPaths: options.MaxPaths, MaxExpanded: options.MaxExpanded,
		IncludeDominated: false, IncludeDiff: false,
	})
	if err != nil {
		return Result{}, fmt.Errorf("analyze report remediation: %w", err)
	}

	allIssues := correlate(findings.Findings, risks.PathScores, remediations.Candidates)
	attachRiskFamilies(allIssues, risks.RiskFamilies)
	for index := range allIssues {
		allIssues[index].AccessExplanations = access.ByRootCause(allIssues[index].RootCauseKey)
	}

	activeRisks := risks
	issues := allIssues
	var baselineSummary *BaselineSummary
	accepted, expired, unmatched := []Exception{}, []Exception{}, []Exception{}
	if options.Baseline != nil {
		evaluatedAt, evaluatedTime := baselineEvaluationTime(options.EvaluatedAt)
		evaluation := baseline.Evaluate(*options.Baseline, findings, risks, evaluatedTime)
		accepted = exceptionsFrom(evaluation.Accepted, allIssues)
		expired = exceptionsFrom(evaluation.Expired, allIssues)
		unmatched = exceptionsFrom(evaluation.Unmatched, allIssues)
		acceptedFindings := evaluation.AcceptedFindingIDs()
		acceptedFamilies := evaluation.AcceptedRiskFamilyIDs()
		acceptedRoots := evaluation.AcceptedRootCauseKeys()
		issues = activeIssues(allIssues, acceptedFindings, acceptedFamilies, acceptedRoots)
		activeRisks = risk.WithoutFamilies(risks, acceptedFamilies)
		baselineSummary = &BaselineSummary{SchemaVersion: baseline.SchemaVersion, Profile: options.Baseline.Profile, EvaluatedAt: evaluatedAt, Entries: len(options.Baseline.Suppressions)}
	}
	activeAllIssues := issues
	totalIssues := len(activeAllIssues)
	if len(issues) > options.MaxIssues {
		issues = issues[:options.MaxIssues]
	}
	warnings := collectWarnings(canonical, findings, risks, remediations)
	warnings = append(warnings, baselineWarnings(expired, unmatched)...)
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].Source != warnings[j].Source {
			return warnings[i].Source < warnings[j].Source
		}
		if warnings[i].Code != warnings[j].Code {
			return warnings[i].Code < warnings[j].Code
		}
		return warnings[i].Message < warnings[j].Message
	})
	warnings = dedupeWarnings(warnings)
	summary := summarize(findings.Findings, activeRisks, remediations, activeAllIssues, issues, totalIssues)
	summary.DetectedRootCauses = len(allIssues)
	summary.AcceptedExceptions = len(accepted)
	summary.ExpiredExceptions = len(expired)
	summary.UnmatchedExceptions = len(unmatched)
	truncated := risks.Truncated || remediations.Truncated || totalIssues > len(issues)
	complete := canonical.Metadata.Complete && findings.Complete && risks.Complete && remediations.Complete && !truncated

	return Result{
		SchemaVersion: ResultSchemaVersion, ModelVersion: ModelVersion,
		ToolVersion: canonical.ToolVersion, SnapshotCollected: canonical.Metadata.CollectedAt,
		ClusterContext: canonical.Metadata.Context, ClusterFingerprint: canonical.Metadata.ClusterFingerprint,
		Namespace: options.Namespace, Complete: complete, Truncated: truncated,
		Inventory: Inventory{
			APIResources: len(canonical.APIResources), Identities: len(canonical.Identities),
			Roles: len(canonical.Roles), Bindings: len(canonical.Bindings),
			ServiceAccounts: len(canonical.ServiceAccounts), Workloads: len(canonical.Workloads),
			Assets: len(canonical.Assets), SecurityControls: len(canonical.SecurityControls),
			CollectionWarnings: len(canonical.Warnings),
		},
		Summary: summary, Issues: issues, Baseline: baselineSummary,
		AcceptedExceptions: accepted, ExpiredExceptions: expired, UnmatchedExceptions: unmatched,
		Warnings: warnings,
	}, nil
}

func baselineEvaluationTime(value string) (string, time.Time) {
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
		return parsed.UTC().Format(time.RFC3339), parsed
	}
	now := time.Now().UTC()
	return now.Format(time.RFC3339), now
}

func attachRiskFamilies(issues []Issue, families []risk.Family) {
	byRoot := make(map[string][]string)
	for _, family := range families {
		byRoot[family.RootCauseKey] = append(byRoot[family.RootCauseKey], family.ID)
	}
	for index := range issues {
		issues[index].RiskFamilyIDs = uniqueSorted(byRoot[issues[index].RootCauseKey])
	}
}

func activeIssues(all []Issue, findingIDs, familyIDs, roots map[string]struct{}) []Issue {
	result := make([]Issue, 0, len(all))
	for _, issue := range all {
		if issueFullyAccepted(issue, findingIDs, familyIDs, roots) {
			continue
		}
		result = append(result, issue)
	}
	return result
}

func issueFullyAccepted(issue Issue, findingIDs, familyIDs, roots map[string]struct{}) bool {
	if _, found := roots[issue.RootCauseKey]; found {
		return true
	}
	if len(issue.FindingIDs) == 0 && len(issue.RiskFamilyIDs) == 0 {
		return false
	}
	for _, id := range issue.FindingIDs {
		if _, found := findingIDs[id]; !found {
			return false
		}
	}
	for _, id := range issue.RiskFamilyIDs {
		if _, found := familyIDs[id]; !found {
			return false
		}
	}
	return len(issue.PathIDs) == 0 || len(issue.RiskFamilyIDs) > 0
}

func issueAccepted(issue Issue, findingIDs, familyIDs, roots map[string]struct{}) bool {
	if _, found := roots[issue.RootCauseKey]; found {
		return true
	}
	for _, id := range issue.FindingIDs {
		if _, found := findingIDs[id]; found {
			return true
		}
	}
	for _, id := range issue.RiskFamilyIDs {
		if _, found := familyIDs[id]; found {
			return true
		}
	}
	return false
}

func exceptionsFrom(matches []baseline.Match, issues []Issue) []Exception {
	result := make([]Exception, 0, len(matches))
	for _, match := range matches {
		findingSet := stringSet(match.FindingIDs)
		familySet := stringSet(match.RiskFamilyIDs)
		rootSet := stringSet(match.RootCauseKeys)
		correlated := make([]Issue, 0)
		for _, issue := range issues {
			if !issueAccepted(issue, findingSet, familySet, rootSet) {
				continue
			}
			acceptedIssue := issue
			acceptedIssue.Actionability = ActionabilityAccepted
			acceptedIssue.Priority = PriorityP3
			correlated = append(correlated, acceptedIssue)
		}
		result = append(result, Exception{Suppression: match.Suppression, State: match.State,
			FindingIDs: match.FindingIDs, RiskFamilyIDs: match.RiskFamilyIDs,
			RootCauseKeys: match.RootCauseKeys, Issues: correlated})
	}
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func baselineWarnings(expired, unmatched []Exception) []Warning {
	result := make([]Warning, 0, len(expired)+len(unmatched))
	for _, value := range expired {
		result = append(result, Warning{Source: "baseline", Code: "EXPIRED_SUPPRESSION", Message: fmt.Sprintf("%s expired on %s and was not applied", value.Suppression.ID, value.Suppression.Expires)})
	}
	for _, value := range unmatched {
		result = append(result, Warning{Source: "baseline", Code: "UNMATCHED_SUPPRESSION", Message: fmt.Sprintf("%s did not match any current finding or risk family", value.Suppression.ID)})
	}
	return result
}

func normalizeOptions(value Options) Options {
	if value.MaxIssues <= 0 {
		value.MaxIssues = defaultMaxIssues
	}
	if value.MaxCandidates <= 0 {
		value.MaxCandidates = defaultMaxCandidates
	}
	if value.MaxPaths <= 0 {
		value.MaxPaths = defaultMaxPaths
	}
	if value.MaxExpanded <= 0 {
		value.MaxExpanded = defaultMaxExpanded
	}
	value.Namespace = strings.TrimSpace(value.Namespace)
	return value
}

type issueBuilder struct {
	issue        Issue
	severity     int
	confidence   int
	pathStates   map[Actionability]int
	pathIDSet    map[string]struct{}
	findingSet   map[string]struct{}
	ruleSet      map[string]struct{}
	recommendSet map[string]struct{}
	evidenceSet  map[string]struct{}
	identitySet  map[string]permission.Identity
	objectSet    map[string]snapshot.ObjectRef
}

func correlate(findings []analysis.Finding, paths []risk.PathScore, candidates []remediation.Candidate) []Issue {
	builders := make(map[string]*issueBuilder)
	for _, finding := range findings {
		for _, rootCause := range findingCauses(finding) {
			builder := ensureBuilder(builders, rootCause.key, rootCause.description, finding.Title)
			builder.addFinding(finding)
		}
	}
	pathOwners := make(map[string][]*issueBuilder)
	for _, scored := range paths {
		if scored.Path == nil {
			continue
		}
		key, cause := pathCause(*scored.Path)
		builder := ensureBuilder(builders, key, cause, scored.Title)
		builder.addPath(scored)
		pathOwners[scored.PathID] = append(pathOwners[scored.PathID], builder)
	}
	for _, candidate := range candidates {
		if candidate.Disposition != remediation.DispositionRecommended {
			continue
		}
		owners := make(map[*issueBuilder]struct{})
		for _, pathID := range candidate.PathIDs {
			for _, builder := range pathOwners[pathID] {
				owners[builder] = struct{}{}
			}
		}
		if len(owners) == 0 {
			key, cause := candidateCause(candidate)
			owners[ensureBuilder(builders, key, cause, candidate.Title)] = struct{}{}
		}
		for builder := range owners {
			builder.issue.Fixes = append(builder.issue.Fixes, fixFrom(candidate))
		}
	}

	result := make([]Issue, 0, len(builders))
	for _, builder := range builders {
		builder.finish()
		result = append(result, builder.issue)
	}
	sort.Slice(result, func(i, j int) bool {
		if priorityRank(result[i].Priority) != priorityRank(result[j].Priority) {
			return priorityRank(result[i].Priority) < priorityRank(result[j].Priority)
		}
		if result[i].MaxPathRisk != result[j].MaxPathRisk {
			return result[i].MaxPathRisk > result[j].MaxPathRisk
		}
		if severityRank(result[i].Severity) != severityRank(result[j].Severity) {
			return severityRank(result[i].Severity) > severityRank(result[j].Severity)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func ensureBuilder(values map[string]*issueBuilder, key, cause, title string) *issueBuilder {
	if current, ok := values[key]; ok {
		return current
	}
	value := &issueBuilder{
		issue: Issue{ID: stableID("issue", key), RootCauseKey: key, RootCause: cause, Title: title,
			Severity: analysis.SeverityInfo, Confidence: attackpath.ConfidenceUnknown,
			AffectedIdentities: []permission.Identity{}, AffectedObjects: []snapshot.ObjectRef{},
			FindingIDs: []string{}, RuleIDs: []string{}, PathIDs: []string{}, RiskFamilyIDs: []string{}, Recommendations: []string{}, Evidence: []string{}, AccessExplanations: []explain.AccessExplanation{}, Fixes: []Fix{}},
		pathStates: make(map[Actionability]int), pathIDSet: make(map[string]struct{}),
		findingSet: make(map[string]struct{}), ruleSet: make(map[string]struct{}),
		recommendSet: make(map[string]struct{}), evidenceSet: make(map[string]struct{}),
		identitySet: make(map[string]permission.Identity), objectSet: make(map[string]snapshot.ObjectRef),
	}
	values[key] = value
	return value
}

func (builder *issueBuilder) addFinding(value analysis.Finding) {
	if rank := severityRank(value.Severity); rank > builder.severity {
		builder.severity = rank
		builder.issue.Severity = value.Severity
		builder.issue.Title = value.Title
		builder.issue.SecurityImpact = value.SecurityImpact
	}
	if confidence := findingConfidence(value.Confidence); confidenceRank(confidence) > builder.confidence {
		builder.confidence = confidenceRank(confidence)
		builder.issue.Confidence = confidence
	}
	builder.findingSet[value.ID] = struct{}{}
	builder.ruleSet[value.RuleID] = struct{}{}
	for _, identity := range value.AffectedIdentities {
		builder.identitySet[identity.String()] = identity
	}
	for _, object := range value.AffectedObjects {
		builder.objectSet[refKey(object)] = object
	}
	for _, recommendation := range value.Recommendations {
		builder.recommendSet[recommendation] = struct{}{}
	}
	for _, evidence := range value.Evidence {
		builder.evidenceSet[evidenceText(evidence)] = struct{}{}
	}
}

func (builder *issueBuilder) addPath(value risk.PathScore) {
	firstPath := len(builder.pathIDSet) == 0
	builder.pathIDSet[value.PathID] = struct{}{}
	if value.Score > builder.issue.MaxPathRisk {
		builder.issue.MaxPathRisk = value.Score
		if builder.issue.SecurityImpact == "" {
			builder.issue.SecurityImpact = value.Target.Description
		}
	}
	if rank := riskSeverityRank(value.Severity); rank > builder.severity {
		builder.severity = rank
		builder.issue.Severity = analysis.Severity(value.Severity)
		builder.issue.Title = value.Title
	}
	if rank := confidenceRank(value.Confidence); firstPath || rank > builder.confidence {
		builder.confidence = rank
		builder.issue.Confidence = value.Confidence
	}
	builder.pathStates[pathActionability(value)]++
	builder.identitySet[value.Source.String()] = value.Source
	if value.Path != nil {
		for _, step := range value.Path.Steps {
			for _, evidence := range step.Evidence {
				builder.evidenceSet[pathEvidenceText(evidence)] = struct{}{}
				if evidence.Ref != nil {
					builder.objectSet[refKey(*evidence.Ref)] = *evidence.Ref
				}
				if evidence.Grant != nil {
					builder.objectSet[refKey(evidence.Grant.BindingRef)] = evidence.Grant.BindingRef
					builder.objectSet[refKey(evidence.Grant.RoleRef)] = evidence.Grant.RoleRef
				}
			}
		}
	}
}

func (builder *issueBuilder) finish() {
	builder.issue.FindingIDs = sortedKeys(builder.findingSet)
	builder.issue.RuleIDs = sortedKeys(builder.ruleSet)
	builder.issue.PathIDs = sortedKeys(builder.pathIDSet)
	builder.issue.Recommendations = sortedKeys(builder.recommendSet)
	builder.issue.Evidence = sortedKeys(builder.evidenceSet)
	for _, identity := range builder.identitySet {
		builder.issue.AffectedIdentities = append(builder.issue.AffectedIdentities, identity)
	}
	sort.Slice(builder.issue.AffectedIdentities, func(i, j int) bool {
		return builder.issue.AffectedIdentities[i].String() < builder.issue.AffectedIdentities[j].String()
	})
	for _, object := range builder.objectSet {
		builder.issue.AffectedObjects = append(builder.issue.AffectedObjects, object)
	}
	sort.Slice(builder.issue.AffectedObjects, func(i, j int) bool {
		return refKey(builder.issue.AffectedObjects[i]) < refKey(builder.issue.AffectedObjects[j])
	})
	sort.Slice(builder.issue.Fixes, func(i, j int) bool {
		if builder.issue.Fixes[i].RiskDelta != builder.issue.Fixes[j].RiskDelta {
			return builder.issue.Fixes[i].RiskDelta < builder.issue.Fixes[j].RiskDelta
		}
		return builder.issue.Fixes[i].ID < builder.issue.Fixes[j].ID
	})
	builder.issue.Actionability = aggregateActionability(builder.pathStates)
	builder.issue.Priority = issuePriority(builder.issue)
}

type cause struct {
	key         string
	description string
}

func findingCauses(value analysis.Finding) []cause {
	result := []cause{}
	seen := make(map[string]struct{})
	for _, evidence := range value.Evidence {
		if evidence.Grant != nil {
			key, description := grantCause(*evidence.Grant)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				result = append(result, cause{key: key, description: description})
			}
		}
	}
	if len(result) > 0 {
		sort.Slice(result, func(i, j int) bool { return result[i].key < result[j].key })
		return result
	}
	if len(value.AffectedIdentities) > 0 {
		for _, object := range value.AffectedObjects {
			if object.Kind != "RoleBinding" && object.Kind != "ClusterRoleBinding" {
				continue
			}
			identity := value.AffectedIdentities[0]
			role := snapshot.ObjectRef{}
			for _, candidate := range value.AffectedObjects {
				if candidate.Kind == "Role" || candidate.Kind == "ClusterRole" {
					role = candidate
					break
				}
			}
			description := fmt.Sprintf("%s receives permissions through %s %s.", identity.String(), object.Kind, displayRef(object))
			if role.Name != "" {
				description = fmt.Sprintf("%s receives permissions through %s %s, which references %s %s.", identity.String(), object.Kind, displayRef(object), role.Kind, displayRef(role))
			}
			return []cause{{key: "grant|" + refKey(object) + "|" + identity.String(), description: description}}
		}
	}
	if len(value.AffectedObjects) > 0 {
		ref := value.AffectedObjects[0]
		return []cause{{key: "object|" + refKey(ref), description: fmt.Sprintf("%s %s contains the configuration that triggered this issue.", ref.Kind, displayRef(ref))}}
	}
	identity := "unscoped"
	if len(value.AffectedIdentities) > 0 {
		identity = value.AffectedIdentities[0].String()
	}
	return []cause{{key: "rule|" + value.RuleID + "|" + identity, description: fmt.Sprintf("Rule %s applies to %s.", value.RuleID, identity)}}
}

func pathCause(value attackpath.Path) (string, string) {
	for _, step := range value.Steps {
		for _, evidence := range step.Evidence {
			if evidence.Grant != nil {
				return grantCause(*evidence.Grant)
			}
		}
	}
	key := "path|" + value.Source.String() + "|" + value.TemplateID + "|" + value.Target.Key
	return key, fmt.Sprintf("%s can reach %s through technique %s.", value.Source.String(), value.Target.Type, value.TemplateID)
}

func grantCause(value permission.GrantEvidence) (string, string) {
	identity := permission.Identity{Kind: value.Subject.Kind, Namespace: value.Subject.Namespace, Name: value.Subject.Name}
	key := "grant|" + refKey(value.BindingRef) + "|" + identity.String()
	cause := fmt.Sprintf("%s receives permissions through %s %s, which references %s %s.", identity.String(), value.BindingRef.Kind, displayRef(value.BindingRef), value.RoleRef.Kind, displayRef(value.RoleRef))
	return key, cause
}

func candidateCause(value remediation.Candidate) (string, string) {
	if value.Change.Subject != nil {
		identity := permission.Identity{Kind: value.Change.Subject.Kind, Namespace: value.Change.Subject.Namespace, Name: value.Change.Subject.Name}
		return "grant|" + refKey(value.Change.Ref) + "|" + identity.String(), fmt.Sprintf("%s receives permissions through %s %s.", identity.String(), value.Change.Ref.Kind, displayRef(value.Change.Ref))
	}
	return "object|" + refKey(value.Change.Ref), fmt.Sprintf("%s %s is the root object for the proposed change.", value.Change.Ref.Kind, displayRef(value.Change.Ref))
}

func fixFrom(value remediation.Candidate) Fix {
	verification := verificationFor(value)
	return Fix{
		ID: value.ID, Title: value.Title, Kind: value.Kind, Disposition: value.Disposition,
		Change: value.Change, Reason: value.Reason,
		RiskBefore: value.Impact.Risk.Cluster.Before, RiskAfter: value.Impact.Risk.Cluster.After,
		RiskDelta: value.Impact.Risk.Cluster.Delta, RemovedPaths: len(value.Impact.RemovedPathIDs),
		BlockedPaths: len(value.Impact.BlockedPathIDs), RemainingPaths: value.Impact.RemainingAttackPaths,
		LostCapabilities: len(value.Impact.LostCapabilities), AffectedIdentities: value.Impact.AffectedIdentities,
		Verification: verification,
		Caution:      "This change was evaluated against snapshot metadata only. Validate workload behavior in a non-production environment before applying it.",
	}
}

func verificationFor(value remediation.Candidate) []string {
	commands := []string{}
	if value.Change.Subject != nil {
		identity := permission.Identity{Kind: value.Change.Subject.Kind, Namespace: value.Change.Subject.Namespace, Name: value.Change.Subject.Name}
		commands = append(commands, fmt.Sprintf("kubectl auth can-i %s '*' '*' --all-namespaces", kubectlIdentityFlags(identity)))
	}
	switch value.Kind {
	case remediation.KindRemoveSubject:
		commands = append(commands, fmt.Sprintf("kubectl get %s %s -o yaml", strings.ToLower(value.Change.Ref.Kind), shellRef(value.Change.Ref)))
	case remediation.KindNarrowRule:
		commands = append(commands, fmt.Sprintf("kubectl get %s %s -o yaml", strings.ToLower(value.Change.Ref.Kind), shellRef(value.Change.Ref)))
	case remediation.KindEnforcePSA:
		commands = append(commands, fmt.Sprintf("kubectl get namespace %s --show-labels", value.Change.Namespace))
	}
	return uniqueSorted(commands)
}

func kubectlIdentityFlags(value permission.Identity) string {
	switch value.Kind {
	case snapshot.IdentityServiceAccount:
		return "--as=system:serviceaccount:" + value.Namespace + ":" + value.Name
	case snapshot.IdentityGroup:
		return "--as=rbacviz-verifier --as-group=" + value.Name
	default:
		return "--as=" + value.Name
	}
}

func findingConfidence(value analysis.Confidence) attackpath.Confidence {
	switch value {
	case analysis.ConfidenceConfirmed:
		return attackpath.ConfidenceConfirmed
	case analysis.ConfidenceLikely:
		return attackpath.ConfidenceLikely
	case analysis.ConfidenceConditional:
		return attackpath.ConfidenceConditional
	case analysis.ConfidenceBlocked:
		return attackpath.ConfidenceBlocked
	default:
		return attackpath.ConfidenceUnknown
	}
}

func filterFindingsByNamespace(values []analysis.Finding, namespace string) []analysis.Finding {
	result := make([]analysis.Finding, 0, len(values))
	for _, value := range values {
		matched := false
		for _, object := range value.AffectedObjects {
			if object.Namespace == namespace || object.Kind == "ClusterRoleBinding" {
				matched = true
				break
			}
		}
		if !matched {
			for _, identity := range value.AffectedIdentities {
				if identity.Namespace == namespace {
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, evidence := range value.Evidence {
				if evidence.Permission != nil && (evidence.Permission.Namespace == namespace || evidence.Permission.Namespace == "*" || evidence.Permission.Scope == permission.ScopeCluster) {
					matched = true
					break
				}
			}
		}
		if matched {
			result = append(result, value)
		}
	}
	return result
}

func pathActionability(value risk.PathScore) Actionability {
	if value.Blocked || value.Confidence == attackpath.ConfidenceBlocked {
		return ActionabilityBlocked
	}
	if value.Confidence == attackpath.ConfidenceConfirmed || value.Confidence == attackpath.ConfidenceLikely {
		return ActionabilityActionable
	}
	return ActionabilityConditional
}

func aggregateActionability(values map[Actionability]int) Actionability {
	if values[ActionabilityActionable] > 0 {
		return ActionabilityActionable
	}
	if values[ActionabilityConditional] > 0 {
		return ActionabilityConditional
	}
	if values[ActionabilityBlocked] > 0 {
		return ActionabilityBlocked
	}
	return ActionabilityObservation
}

func issuePriority(value Issue) Priority {
	hasFix := len(value.Fixes) > 0
	switch value.Actionability {
	case ActionabilityBlocked:
		return PriorityP3
	case ActionabilityConditional:
		if value.Severity == analysis.SeverityCritical {
			return PriorityP1
		}
		return PriorityP2
	}
	if value.Severity == analysis.SeverityCritical && value.Actionability == ActionabilityActionable && hasFix {
		return PriorityP0
	}
	if value.Severity == analysis.SeverityCritical || (value.Severity == analysis.SeverityHigh && hasFix) {
		return PriorityP1
	}
	if value.Severity == analysis.SeverityHigh || value.Severity == analysis.SeverityMedium {
		return PriorityP2
	}
	return PriorityP3
}

func summarize(findings []analysis.Finding, risks risk.Result, remediations remediation.Result, active, included []Issue, total int) Summary {
	result := Summary{
		RiskModelVersion: risk.ModelVersion, RiskIndex: risks.Cluster.Score, RiskSeverity: risks.Cluster.Severity,
		RiskFamilies: len(risks.RiskFamilies), ContributingRiskFamilies: risks.Cluster.ContributingFamilies,
		RawFindings: len(findings), RootCauses: total, IncludedIssues: len(included),
		OmittedIssues: total - len(included), AttackPaths: len(risks.PathScores),
	}
	_ = remediations // completeness and warnings still come from the remediation result.
	for _, issue := range active {
		result.RecommendedFixes += len(issue.Fixes)
	}
	for _, value := range risks.PathScores {
		switch pathActionability(value) {
		case ActionabilityActionable:
			result.ActionablePaths++
		case ActionabilityConditional:
			result.ConditionalPaths++
		case ActionabilityBlocked:
			result.BlockedPaths++
		}
	}
	for _, issue := range included {
		switch issue.Priority {
		case PriorityP0:
			result.PriorityP0++
		case PriorityP1:
			result.PriorityP1++
		case PriorityP2:
			result.PriorityP2++
		case PriorityP3:
			result.PriorityP3++
		}
	}
	return result
}

func collectWarnings(input snapshot.Snapshot, findings analysis.Result, risks risk.Result, remediations remediation.Result) []Warning {
	result := []Warning{}
	for _, value := range input.Warnings {
		result = append(result, Warning{Source: "collection", Code: value.Code, Message: value.Resource + ": " + value.Message})
	}
	for _, value := range findings.Warnings {
		result = append(result, Warning{Source: "findings", Code: value.Code, Message: value.Message})
	}
	for _, value := range risks.Warnings {
		result = append(result, Warning{Source: "risk", Code: value.Code, Message: value.Message})
	}
	for _, value := range remediations.Warnings {
		result = append(result, Warning{Source: "remediation", Code: value.Code, Message: value.Message})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		if result[i].Code != result[j].Code {
			return result[i].Code < result[j].Code
		}
		return result[i].Message < result[j].Message
	})
	return dedupeWarnings(result)
}

func evidenceText(value analysis.Evidence) string {
	if value.Grant != nil {
		return fmt.Sprintf("grant %s via %s %s -> %s %s", value.Grant.ID, value.Grant.BindingRef.Kind, displayRef(value.Grant.BindingRef), value.Grant.RoleRef.Kind, displayRef(value.Grant.RoleRef))
	}
	if value.Permission != nil {
		return fmt.Sprintf("permission %s %s namespace=%s scope=%s", value.Permission.Verb, resourceName(value.Permission.Resource, value.Permission.Subresource, value.Permission.APIGroup), value.Permission.Namespace, value.Permission.Scope)
	}
	if value.Ref != nil {
		return fmt.Sprintf("%s %s field=%s value=%s", value.Ref.Kind, displayRef(*value.Ref), value.Field, value.Value)
	}
	return strings.TrimSpace(value.Kind + " " + value.Field + " " + value.Value)
}

func pathEvidenceText(value attackpath.StepEvidence) string {
	if value.Grant != nil {
		return fmt.Sprintf("grant %s via %s %s -> %s %s", value.Grant.ID, value.Grant.BindingRef.Kind, displayRef(value.Grant.BindingRef), value.Grant.RoleRef.Kind, displayRef(value.Grant.RoleRef))
	}
	if value.Permission != nil {
		return fmt.Sprintf("permission %s %s namespace=%s scope=%s", value.Permission.Verb, resourceName(value.Permission.Resource, value.Permission.Subresource, value.Permission.APIGroup), value.Permission.Namespace, value.Permission.Scope)
	}
	if value.Ref != nil {
		return fmt.Sprintf("%s %s field=%s value=%s", value.Ref.Kind, displayRef(*value.Ref), value.Field, value.Value)
	}
	return strings.TrimSpace(value.Field + " " + value.Value)
}

func resourceName(resource, subresource, group string) string {
	result := resource
	if subresource != "" {
		result += "/" + subresource
	}
	if group != "" {
		result += "." + group
	}
	return result
}

func displayRef(value snapshot.ObjectRef) string {
	if value.Namespace == "" {
		return value.Name
	}
	return value.Namespace + "/" + value.Name
}

func shellRef(value snapshot.ObjectRef) string {
	if value.Namespace == "" {
		return value.Name
	}
	return value.Name + " -n " + value.Namespace
}

func refKey(value snapshot.ObjectRef) string {
	return strings.Join([]string{value.APIGroup, value.Kind, value.Namespace, value.Name}, "|")
}

func stableID(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + "-" + hex.EncodeToString(digest[:])[:24]
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	if len(values) == 0 {
		return []string{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] != values[write-1] {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}

func dedupeWarnings(values []Warning) []Warning {
	if len(values) == 0 {
		return []Warning{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] != values[write-1] {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}

func severityRank(value analysis.Severity) int {
	switch value {
	case analysis.SeverityCritical:
		return 5
	case analysis.SeverityHigh:
		return 4
	case analysis.SeverityMedium:
		return 3
	case analysis.SeverityLow:
		return 2
	case analysis.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func riskSeverityRank(value risk.Severity) int { return severityRank(analysis.Severity(value)) }

func confidenceRank(value attackpath.Confidence) int {
	switch value {
	case attackpath.ConfidenceConfirmed:
		return 5
	case attackpath.ConfidenceLikely:
		return 4
	case attackpath.ConfidenceConditional:
		return 3
	case attackpath.ConfidenceUnknown:
		return 2
	case attackpath.ConfidenceBlocked:
		return 1
	default:
		return 0
	}
}

func priorityRank(value Priority) int {
	switch value {
	case PriorityP0:
		return 0
	case PriorityP1:
		return 1
	case PriorityP2:
		return 2
	default:
		return 3
	}
}
