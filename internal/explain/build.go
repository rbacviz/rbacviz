package explain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type explanationBuilder struct {
	value             AccessExplanation
	capabilities      map[string]*CapabilitySummary
	findingSet        map[string]struct{}
	ruleSet           map[string]struct{}
	pathSet           map[string]struct{}
	relatedSet        map[string]struct{}
	recommendationSet map[string]struct{}
	verificationSet   map[string]struct{}
	preconditionSet   map[string]struct{}
	mitigationSet     map[string]struct{}
	pathStates        map[Status]int
	severityRank      int
	confidenceRank    int
}

// Build resolves every observed identity and correlates effective permissions,
// findings, and attack paths around exact binding/subject root causes. It does
// not contact or modify a cluster.
func Build(ctx context.Context, input snapshot.Snapshot, nodes []graphmodel.Node, findings analysis.Result, paths attackpath.Result, risks risk.Result) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize access explanation input: %w", err)
	}
	resolver, err := permission.New(canonical)
	if err != nil {
		return Result{}, fmt.Errorf("initialize access explanation resolver: %w", err)
	}

	builders := make(map[string]*explanationBuilder)
	identities := observedIdentities(canonical)
	for _, identity := range identities {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		resolved := resolver.Permissions(identity, nil)
		for _, capability := range resolved.Capabilities {
			for _, grant := range capability.Grants {
				builder := ensureBuilder(builders, grant)
				builder.addCapability(capability, grant)
			}
		}
	}

	indexes := objectIndexes(canonical)
	for _, builder := range builders {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		builder.addRelated(indexes[refKey(builder.value.Binding)]...)
		builder.addRelated(indexes[refKey(builder.value.Role)]...)
		builder.addRelated(indexes[identityKey(builder.value.Subject)]...)
		builder.value.Workloads = matchingWorkloads(canonical.Workloads, builder.value.Subject)
		for _, workload := range builder.value.Workloads {
			builder.addRelated(indexes[refKey(workload)]...)
		}
		builder.addRelated("namespace:" + effectiveNamespace(builder.value))
	}

	correlateFindings(builders, findings.Findings)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	correlatePaths(builders, paths.Paths, risks.PathScores)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	indexCapabilityNodes(builders, nodes)

	result := make([]AccessExplanation, 0, len(builders))
	for _, builder := range builders {
		builder.finish()
		result = append(result, builder.value)
	}
	sort.Slice(result, func(i, j int) bool {
		if priorityRank(result[i].Analysis.Priority) != priorityRank(result[j].Analysis.Priority) {
			return priorityRank(result[i].Analysis.Priority) < priorityRank(result[j].Analysis.Priority)
		}
		if result[i].Analysis.MaxPathRisk != result[j].Analysis.MaxPathRisk {
			return result[i].Analysis.MaxPathRisk > result[j].Analysis.MaxPathRisk
		}
		if severityRank(result[i].Analysis.Severity) != severityRank(result[j].Analysis.Severity) {
			return severityRank(result[i].Analysis.Severity) > severityRank(result[j].Analysis.Severity)
		}
		return result[i].ID < result[j].ID
	})

	warnings := collectWarnings(canonical, findings, paths, risks)
	complete := canonical.Metadata.Complete && findings.Complete && risks.Complete
	if paths.SchemaVersion != "" {
		complete = complete && paths.Complete && !paths.Truncated
	}
	output := Result{SchemaVersion: ResultSchemaVersion, ModelVersion: ModelVersion, Complete: complete, Explanations: result, Warnings: warnings}
	output.buildIndexes()
	return output, nil
}

func ensureBuilder(values map[string]*explanationBuilder, grant permission.GrantEvidence) *explanationBuilder {
	subject := permission.Identity{Kind: grant.Subject.Kind, Namespace: grant.Subject.Namespace, Name: grant.Subject.Name}
	key := grantRootCauseKey(grant.BindingRef, subject)
	if current, ok := values[key]; ok {
		current.addRelated(grant.ID, grant.PolicyRuleID)
		current.mergeAggregation(grant.AggregationChain)
		return current
	}
	value := &explanationBuilder{
		value: AccessExplanation{
			ID: stableID("access", key), RootCauseKey: key, Subject: subject,
			Binding: grant.BindingRef, Role: grant.RoleRef,
			AggregationChain: append([]snapshot.ObjectRef(nil), grant.AggregationChain...),
			Capabilities:     []CapabilitySummary{}, FindingIDs: []string{}, RuleIDs: []string{}, PathIDs: []string{}, RelatedIDs: []string{},
			Analysis: Analysis{Priority: PriorityP3, Status: StatusObservation, Severity: analysis.SeverityInfo,
				Confidence: attackpath.ConfidenceConfirmed, Recommendations: []string{}, Verification: []string{}, Preconditions: []string{}, Mitigations: []string{}},
		},
		capabilities: make(map[string]*CapabilitySummary), findingSet: make(map[string]struct{}),
		ruleSet: make(map[string]struct{}), pathSet: make(map[string]struct{}), relatedSet: make(map[string]struct{}),
		recommendationSet: make(map[string]struct{}), verificationSet: make(map[string]struct{}),
		preconditionSet: make(map[string]struct{}), mitigationSet: make(map[string]struct{}), pathStates: make(map[Status]int),
	}
	value.value.Analysis.RootCause = rootCauseText(value.value)
	value.addRelated(value.value.ID, grant.ID, grant.PolicyRuleID)
	values[key] = value
	return value
}

func (builder *explanationBuilder) addCapability(value permission.Capability, grant permission.GrantEvidence) {
	key := capabilityKey(value)
	current, ok := builder.capabilities[key]
	if !ok {
		current = &CapabilitySummary{
			Verb: value.Verb, APIGroup: value.APIGroup, Resource: value.Resource, Subresource: value.Subresource,
			ResourceNames: append([]string(nil), value.ResourceNames...), NonResourceURL: value.NonResourceURL,
			Scope: value.Scope, Namespace: value.Namespace, GrantIDs: []string{}, FindingIDs: []string{}, PathIDs: []string{},
			Severity: analysis.SeverityInfo, Confidence: attackpath.ConfidenceConfirmed,
		}
		builder.capabilities[key] = current
	}
	current.GrantIDs = appendUnique(current.GrantIDs, grant.ID)
	builder.ruleSet[grant.PolicyRuleID] = struct{}{}
	builder.addRelated(grant.ID, grant.PolicyRuleID)
	builder.verificationSet[verificationCommand(builder.value.Subject, *current)] = struct{}{}
}

func (builder *explanationBuilder) addFinding(value analysis.Finding, grantID string) {
	builder.findingSet[value.ID] = struct{}{}
	builder.ruleSet[value.RuleID] = struct{}{}
	builder.addRelated(value.ID, value.RuleID)
	if rank := severityRank(value.Severity); rank > builder.severityRank {
		builder.severityRank = rank
		builder.value.Analysis.Severity = value.Severity
		builder.value.Analysis.Impact = value.SecurityImpact
	}
	confidence := findingConfidence(value.Confidence)
	if rank := confidenceRank(confidence); rank > builder.confidenceRank {
		builder.confidenceRank = rank
		builder.value.Analysis.Confidence = confidence
	}
	for _, recommendation := range value.Recommendations {
		builder.recommendationSet[recommendation] = struct{}{}
	}
	for _, precondition := range value.Preconditions {
		builder.preconditionSet[precondition] = struct{}{}
	}
	for _, mitigation := range value.MitigatingControls {
		builder.mitigationSet[mitigation] = struct{}{}
	}
	permissions := findingPermissions(value)
	for _, capability := range builder.capabilities {
		if !contains(capability.GrantIDs, grantID) {
			continue
		}
		if len(permissions) > 0 && !matchesAny(*capability, permissions) {
			continue
		}
		capability.FindingIDs = appendUnique(capability.FindingIDs, value.ID)
		if severityRank(value.Severity) > severityRank(capability.Severity) {
			capability.Severity = value.Severity
		}
		if confidenceRank(confidence) > confidenceRank(capability.Confidence) {
			capability.Confidence = confidence
		}
	}
}

func (builder *explanationBuilder) addPath(value risk.PathScore, path attackpath.Path, grantID string) {
	builder.pathSet[value.PathID] = struct{}{}
	builder.addRelated(value.PathID, value.ID)
	status := pathStatus(value)
	builder.pathStates[status]++
	if value.Score > builder.value.Analysis.MaxPathRisk {
		builder.value.Analysis.MaxPathRisk = value.Score
		if builder.value.Analysis.Impact == "" {
			builder.value.Analysis.Impact = value.Target.Description
		}
	}
	severity := analysis.Severity(value.Severity)
	if rank := severityRank(severity); rank > builder.severityRank {
		builder.severityRank = rank
		builder.value.Analysis.Severity = severity
	}
	if rank := confidenceRank(value.Confidence); rank > builder.confidenceRank {
		builder.confidenceRank = rank
		builder.value.Analysis.Confidence = value.Confidence
	}
	permissions := pathPermissions(path, grantID)
	for _, capability := range builder.capabilities {
		if !contains(capability.GrantIDs, grantID) {
			continue
		}
		if len(permissions) > 0 && !matchesAny(*capability, permissions) {
			continue
		}
		capability.PathIDs = appendUnique(capability.PathIDs, value.PathID)
		if value.Score > capability.Risk {
			capability.Risk = value.Score
		}
		if severityRank(severity) > severityRank(capability.Severity) {
			capability.Severity = severity
		}
		if confidenceRank(value.Confidence) > confidenceRank(capability.Confidence) {
			capability.Confidence = value.Confidence
		}
	}
}

func (builder *explanationBuilder) finish() {
	for _, capability := range builder.capabilities {
		capability.GrantIDs = uniqueSorted(capability.GrantIDs)
		capability.FindingIDs = uniqueSorted(capability.FindingIDs)
		capability.PathIDs = uniqueSorted(capability.PathIDs)
		builder.value.Capabilities = append(builder.value.Capabilities, *capability)
	}
	sort.Slice(builder.value.Capabilities, func(i, j int) bool {
		return capabilitySummaryKey(builder.value.Capabilities[i]) < capabilitySummaryKey(builder.value.Capabilities[j])
	})
	builder.value.FindingIDs = sortedKeys(builder.findingSet)
	builder.value.RuleIDs = sortedKeys(builder.ruleSet)
	builder.value.PathIDs = sortedKeys(builder.pathSet)
	builder.value.RelatedIDs = sortedKeys(builder.relatedSet)
	builder.value.Analysis.Recommendations = sortedKeys(builder.recommendationSet)
	builder.value.Analysis.Verification = builder.prioritizedVerification()
	builder.value.Analysis.Preconditions = sortedKeys(builder.preconditionSet)
	builder.value.Analysis.Mitigations = sortedKeys(builder.mitigationSet)
	builder.value.Analysis.Status = aggregateStatus(builder.pathStates)
	builder.value.Analysis.Priority = priority(builder.value.Analysis)
	if len(builder.value.Analysis.Recommendations) == 0 {
		builder.value.Analysis.Recommendations = []string{"No evidence-backed change was selected. Review the effective permissions and workload requirements before narrowing this grant."}
	}
	if builder.value.Analysis.Impact == "" {
		builder.value.Analysis.Impact = "No security rule or attack path is currently correlated with this grant. It remains visible as an access observation."
	}
	sort.Slice(builder.value.Workloads, func(i, j int) bool { return refKey(builder.value.Workloads[i]) < refKey(builder.value.Workloads[j]) })
	sort.Slice(builder.value.AggregationChain, func(i, j int) bool {
		return refKey(builder.value.AggregationChain[i]) < refKey(builder.value.AggregationChain[j])
	})
}

func (builder *explanationBuilder) prioritizedVerification() []string {
	capabilities := append([]CapabilitySummary(nil), builder.value.Capabilities...)
	sort.Slice(capabilities, func(i, j int) bool {
		if severityRank(capabilities[i].Severity) != severityRank(capabilities[j].Severity) {
			return severityRank(capabilities[i].Severity) > severityRank(capabilities[j].Severity)
		}
		if capabilities[i].Risk != capabilities[j].Risk {
			return capabilities[i].Risk > capabilities[j].Risk
		}
		return capabilitySummaryKey(capabilities[i]) < capabilitySummaryKey(capabilities[j])
	})
	result := make([]string, 0, len(builder.verificationSet))
	for _, capability := range capabilities {
		result = appendUnique(result, verificationCommand(builder.value.Subject, capability))
	}
	for _, command := range sortedKeys(builder.verificationSet) {
		result = appendUnique(result, command)
	}
	return result
}

func correlateFindings(builders map[string]*explanationBuilder, values []analysis.Finding) {
	for _, finding := range values {
		grantIDs := make(map[string]struct{})
		for _, evidence := range finding.Evidence {
			if evidence.Grant != nil {
				grantIDs[evidence.Grant.ID] = struct{}{}
			}
		}
		for _, builder := range builders {
			matched := false
			for grantID := range grantIDs {
				if builder.hasGrant(grantID) {
					builder.addFinding(finding, grantID)
					matched = true
				}
			}
			if !matched && len(grantIDs) == 0 && findingAffectsIdentity(finding, builder.value.Subject) && findingAffectsBinding(finding, builder.value.Binding) {
				builder.addFinding(finding, "")
			}
		}
	}
}

func correlatePaths(builders map[string]*explanationBuilder, detailed []attackpath.Path, values []risk.PathScore) {
	paths := make(map[string]attackpath.Path, len(detailed))
	for _, path := range detailed {
		paths[path.ID] = path
	}
	for _, scored := range values {
		path := paths[scored.PathID]
		if scored.Path != nil {
			path = *scored.Path
		}
		grants := pathGrantIDs(path)
		for _, builder := range builders {
			for grantID := range grants {
				if builder.hasGrant(grantID) {
					builder.addPath(scored, path, grantID)
				}
			}
		}
	}
}

func indexCapabilityNodes(builders map[string]*explanationBuilder, nodes []graphmodel.Node) {
	for _, node := range nodes {
		if node.Type != graphmodel.NodeCapability || node.Capability == nil {
			continue
		}
		for _, builder := range builders {
			for _, capability := range builder.capabilities {
				if sameCapability(*capability, *node.Capability) {
					builder.addRelated(node.ID)
					break
				}
			}
		}
	}
}

func (builder *explanationBuilder) hasGrant(id string) bool {
	for _, capability := range builder.capabilities {
		if contains(capability.GrantIDs, id) {
			return true
		}
	}
	return false
}

func (builder *explanationBuilder) addRelated(values ...string) {
	for _, value := range values {
		if strings.TrimSpace(value) != "" && value != "namespace:" {
			builder.relatedSet[value] = struct{}{}
		}
	}
}

func (builder *explanationBuilder) mergeAggregation(values []snapshot.ObjectRef) {
	seen := make(map[string]struct{}, len(builder.value.AggregationChain)+len(values))
	for _, value := range builder.value.AggregationChain {
		seen[refKey(value)] = struct{}{}
	}
	for _, value := range values {
		if _, ok := seen[refKey(value)]; !ok {
			builder.value.AggregationChain = append(builder.value.AggregationChain, value)
			seen[refKey(value)] = struct{}{}
		}
	}
}

func observedIdentities(value snapshot.Snapshot) []permission.Identity {
	values := make(map[string]permission.Identity)
	for _, identity := range value.Identities {
		current := permission.Identity{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name}
		values[identityKey(current)] = current
	}
	for _, account := range value.ServiceAccounts {
		current := permission.Identity{Kind: snapshot.IdentityServiceAccount, Namespace: account.Ref.Namespace, Name: account.Ref.Name}
		values[identityKey(current)] = current
	}
	for _, binding := range value.Bindings {
		for _, subject := range binding.Subjects {
			current := permission.Identity{Kind: subject.Kind, Namespace: subject.Namespace, Name: subject.Name}
			values[identityKey(current)] = current
		}
	}
	result := make([]permission.Identity, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func objectIndexes(value snapshot.Snapshot) map[string][]string {
	result := make(map[string][]string)
	for _, identity := range value.Identities {
		key := identityKey(permission.Identity{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name})
		result[key] = append(result[key], identity.ID)
	}
	for _, role := range value.Roles {
		result[refKey(role.Ref)] = append(result[refKey(role.Ref)], role.ID)
	}
	for _, binding := range value.Bindings {
		result[refKey(binding.Ref)] = append(result[refKey(binding.Ref)], binding.ID)
	}
	for _, account := range value.ServiceAccounts {
		result[refKey(account.Ref)] = append(result[refKey(account.Ref)], account.ID)
		key := identityKey(permission.Identity{Kind: snapshot.IdentityServiceAccount, Namespace: account.Ref.Namespace, Name: account.Ref.Name})
		result[key] = append(result[key], account.ID)
	}
	for _, workload := range value.Workloads {
		result[refKey(workload.Ref)] = append(result[refKey(workload.Ref)], workload.ID)
	}
	return result
}

func matchingWorkloads(values []snapshot.Workload, identity permission.Identity) []snapshot.ObjectRef {
	if identity.Kind != snapshot.IdentityServiceAccount {
		return []snapshot.ObjectRef{}
	}
	result := make([]snapshot.ObjectRef, 0)
	for _, workload := range values {
		if workload.Ref.Namespace == identity.Namespace && workload.ServiceAccountName == identity.Name {
			result = append(result, workload.Ref)
		}
	}
	return result
}

func findingPermissions(value analysis.Finding) []analysis.PermissionEvidence {
	result := make([]analysis.PermissionEvidence, 0)
	for _, evidence := range value.Evidence {
		if evidence.Permission != nil {
			result = append(result, *evidence.Permission)
		}
	}
	return result
}

func pathPermissions(value attackpath.Path, grantID string) []analysis.PermissionEvidence {
	result := make([]analysis.PermissionEvidence, 0)
	for _, step := range value.Steps {
		stepHasGrant := false
		for _, evidence := range step.Evidence {
			if evidence.Grant != nil && evidence.Grant.ID == grantID {
				stepHasGrant = true
			}
		}
		if !stepHasGrant {
			continue
		}
		for _, evidence := range step.Evidence {
			if evidence.Permission != nil {
				result = append(result, analysis.PermissionEvidence{
					Verb: evidence.Permission.Verb, APIGroup: evidence.Permission.APIGroup, Resource: evidence.Permission.Resource,
					Subresource: evidence.Permission.Subresource, ResourceNames: append([]string(nil), evidence.Permission.ResourceNames...),
					Scope: evidence.Permission.Scope, Namespace: evidence.Permission.Namespace,
				})
			}
		}
	}
	return result
}

func pathGrantIDs(value attackpath.Path) map[string]struct{} {
	result := make(map[string]struct{})
	for _, step := range value.Steps {
		for _, evidence := range step.Evidence {
			if evidence.Grant != nil {
				result[evidence.Grant.ID] = struct{}{}
			}
		}
	}
	return result
}

func matchesAny(capability CapabilitySummary, values []analysis.PermissionEvidence) bool {
	for _, value := range values {
		if capability.Verb == value.Verb && capability.APIGroup == value.APIGroup && capability.Resource == value.Resource && capability.Subresource == value.Subresource && capability.Scope == value.Scope && capability.Namespace == value.Namespace {
			return true
		}
	}
	return false
}

func sameCapability(left CapabilitySummary, right permission.Capability) bool {
	return left.Verb == right.Verb && left.APIGroup == right.APIGroup && left.Resource == right.Resource && left.Subresource == right.Subresource && left.NonResourceURL == right.NonResourceURL && left.Scope == right.Scope && left.Namespace == right.Namespace && strings.Join(left.ResourceNames, "\x00") == strings.Join(right.ResourceNames, "\x00")
}

func findingAffectsIdentity(value analysis.Finding, identity permission.Identity) bool {
	for _, candidate := range value.AffectedIdentities {
		if candidate == identity {
			return true
		}
	}
	return false
}

func findingAffectsBinding(value analysis.Finding, binding snapshot.ObjectRef) bool {
	for _, candidate := range value.AffectedObjects {
		if refKey(candidate) == refKey(binding) {
			return true
		}
	}
	return false
}

func rootCauseText(value AccessExplanation) string {
	scope := "cluster-wide or API-path access"
	if value.Binding.Kind == "RoleBinding" {
		scope = "namespace " + value.Binding.Namespace
	}
	return fmt.Sprintf("%s receives permissions through %s %s, which references %s %s; effective access is %s.", value.Subject.String(), value.Binding.Kind, displayRef(value.Binding), value.Role.Kind, displayRef(value.Role), scope)
}

func effectiveNamespace(value AccessExplanation) string {
	if value.Binding.Kind == "RoleBinding" {
		return value.Binding.Namespace
	}
	return ""
}

func verificationCommand(identity permission.Identity, capability CapabilitySummary) string {
	resource := capability.Resource
	if capability.NonResourceURL != "" {
		return fmt.Sprintf("kubectl auth can-i %s %s %s", capability.Verb, capability.NonResourceURL, identityFlags(identity))
	}
	if capability.Subresource != "" {
		resource += "/" + capability.Subresource
	}
	if capability.APIGroup != "" {
		resource += "." + capability.APIGroup
	}
	command := fmt.Sprintf("kubectl auth can-i %s %s %s", capability.Verb, resource, identityFlags(identity))
	if capability.Scope == permission.ScopeNamespaced {
		if capability.Namespace == "*" {
			command += " --all-namespaces"
		} else if capability.Namespace != "" {
			command += " -n " + capability.Namespace
		}
	}
	return command
}

func identityFlags(value permission.Identity) string {
	switch value.Kind {
	case snapshot.IdentityServiceAccount:
		return "--as=system:serviceaccount:" + value.Namespace + ":" + value.Name
	case snapshot.IdentityGroup:
		return "--as=rbacviz-verifier --as-group=" + value.Name
	default:
		return "--as=" + value.Name
	}
}

func aggregateStatus(values map[Status]int) Status {
	if values[StatusActionable] > 0 {
		return StatusActionable
	}
	if values[StatusConditional] > 0 {
		return StatusConditional
	}
	if values[StatusBlocked] > 0 {
		return StatusBlocked
	}
	return StatusObservation
}

func pathStatus(value risk.PathScore) Status {
	if value.Blocked || value.Confidence == attackpath.ConfidenceBlocked {
		return StatusBlocked
	}
	if value.Confidence == attackpath.ConfidenceConfirmed || value.Confidence == attackpath.ConfidenceLikely {
		return StatusActionable
	}
	return StatusConditional
}

func priority(value Analysis) Priority {
	if value.Status == StatusBlocked {
		return PriorityP3
	}
	if value.Severity == analysis.SeverityCritical || (value.Status == StatusActionable && value.Severity == analysis.SeverityHigh) {
		return PriorityP1
	}
	if value.Severity == analysis.SeverityHigh || value.Severity == analysis.SeverityMedium || value.Status == StatusConditional {
		return PriorityP2
	}
	return PriorityP3
}

func findingConfidence(value analysis.Confidence) attackpath.Confidence {
	return attackpath.Confidence(value)
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

func collectWarnings(input snapshot.Snapshot, findings analysis.Result, paths attackpath.Result, risks risk.Result) []Warning {
	values := make([]Warning, 0)
	for _, value := range input.Warnings {
		values = append(values, Warning{Code: "Collection." + value.Code, Message: value.Resource + ": " + value.Message})
	}
	for _, value := range findings.Warnings {
		values = append(values, Warning{Code: "Findings." + value.Code, Message: value.Message})
	}
	for _, value := range paths.Warnings {
		values = append(values, Warning{Code: "AttackPath." + value.Code, Message: value.Message})
	}
	for _, value := range risks.Warnings {
		values = append(values, Warning{Code: "Risk." + value.Code, Message: value.Message})
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].Code+"\x00"+values[i].Message < values[j].Code+"\x00"+values[j].Message
	})
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

func grantRootCauseKey(binding snapshot.ObjectRef, identity permission.Identity) string {
	return "grant|" + refKey(binding) + "|" + identity.String()
}

func refKey(value snapshot.ObjectRef) string {
	return strings.Join([]string{value.APIGroup, value.Kind, value.Namespace, value.Name}, "|")
}

func identityKey(value permission.Identity) string {
	return strings.Join([]string{string(value.Kind), value.Namespace, value.Name}, "|")
}

func capabilityKey(value permission.Capability) string {
	return strings.Join([]string{value.Verb, value.APIGroup, value.Resource, value.Subresource, value.NonResourceURL, string(value.Scope), value.Namespace, strings.Join(value.ResourceNames, ",")}, "|")
}

func capabilitySummaryKey(value CapabilitySummary) string {
	return strings.Join([]string{value.Resource, value.APIGroup, value.Subresource, value.NonResourceURL, value.Verb, string(value.Scope), value.Namespace, strings.Join(value.ResourceNames, ",")}, "|")
}

func displayRef(value snapshot.ObjectRef) string {
	if value.Namespace == "" {
		return value.Name
	}
	return value.Namespace + "/" + value.Name
}

func stableID(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + "-" + hex.EncodeToString(digest[:])[:24]
}

func appendUnique(values []string, candidate string) []string {
	if candidate == "" || contains(values, candidate) {
		return values
	}
	return append(values, candidate)
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
