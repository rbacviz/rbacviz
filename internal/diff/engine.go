package diff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	defaultMaxPaths    = 10000
	defaultMaxExpanded = 100000
)

// Compare runs the same permission, finding, attack-path, and risk engines on
// both sides and returns their deterministic semantic delta.
func Compare(ctx context.Context, beforeInput, afterInput snapshot.Snapshot, options Options) (Result, error) {
	before, err := snapshot.Canonicalize(beforeInput)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize before snapshot: %w", err)
	}
	after, err := snapshot.Canonicalize(afterInput)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize after snapshot: %w", err)
	}
	if options.MaxPaths <= 0 {
		options.MaxPaths = defaultMaxPaths
	}
	if options.MaxExpanded <= 0 {
		options.MaxExpanded = defaultMaxExpanded
	}
	beforeDigest, err := snapshot.SemanticDigest(before)
	if err != nil {
		return Result{}, err
	}
	afterDigest, err := snapshot.SemanticDigest(after)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		SchemaVersion: ResultSchemaVersion, BeforeSemanticDigest: beforeDigest, AfterSemanticDigest: afterDigest,
		Objects:     ObjectDiff{Added: []ObjectSummary{}, Removed: []ObjectSummary{}, Modified: []ObjectModification{}},
		Identities:  IdentityDiff{Added: []permission.Identity{}, Removed: []permission.Identity{}},
		Permissions: []PermissionDiff{}, DangerousCapabilities: []DangerousCapabilityChange{},
		Findings:    FindingDiff{Added: []FindingSummary{}, Removed: []FindingSummary{}},
		AttackPaths: AttackPathDiff{Added: []PathSummary{}, Removed: []PathSummary{}, ChangedState: []PathStateChange{}},
		Controls:    ControlDiff{Added: []snapshot.SecurityControl{}, Removed: []snapshot.SecurityControl{}, Modified: []ControlChange{}},
		Risk:        RiskDiff{Identities: []ScoreDelta{}, Namespaces: []ScoreDelta{}}, Warnings: []Warning{},
	}
	result.Objects = compareObjects(before, after)
	result.Identities = compareIdentities(before.Identities, after.Identities)
	result.Controls = compareControls(before.SecurityControls, after.SecurityControls)

	permissionDiff, dangerous, permissionWarnings, err := comparePermissions(ctx, before, after)
	if err != nil {
		return Result{}, err
	}
	result.Permissions = permissionDiff
	result.DangerousCapabilities = dangerous
	result.Warnings = append(result.Warnings, permissionWarnings...)

	beforeFindings, err := analyzeFindings(ctx, before)
	if err != nil {
		return Result{}, fmt.Errorf("analyze before findings: %w", err)
	}
	afterFindings, err := analyzeFindings(ctx, after)
	if err != nil {
		return Result{}, fmt.Errorf("analyze after findings: %w", err)
	}
	result.Findings = compareFindings(beforeFindings, afterFindings)
	appendFindingWarnings(&result.Warnings, "before", beforeFindings.Warnings)
	appendFindingWarnings(&result.Warnings, "after", afterFindings.Warnings)

	pathQuery := attackpath.Query{Top: options.MaxPaths, MaxExpanded: options.MaxExpanded}
	beforePaths, err := analyzePaths(ctx, before, pathQuery)
	if err != nil {
		return Result{}, fmt.Errorf("analyze before attack paths: %w", err)
	}
	afterPaths, err := analyzePaths(ctx, after, pathQuery)
	if err != nil {
		return Result{}, fmt.Errorf("analyze after attack paths: %w", err)
	}
	result.AttackPaths = comparePaths(beforePaths.Paths, afterPaths.Paths)
	appendPathWarnings(&result.Warnings, "before", beforePaths.Warnings)
	appendPathWarnings(&result.Warnings, "after", afterPaths.Warnings)

	riskQuery := risk.Query{MaxPaths: options.MaxPaths, MaxExpanded: options.MaxExpanded}
	beforeRisk, err := analyzeRisk(ctx, before, riskQuery)
	if err != nil {
		return Result{}, fmt.Errorf("analyze before risk: %w", err)
	}
	afterRisk, err := analyzeRisk(ctx, after, riskQuery)
	if err != nil {
		return Result{}, fmt.Errorf("analyze after risk: %w", err)
	}
	result.Risk = compareRisk(beforeRisk, afterRisk)
	appendRiskWarnings(&result.Warnings, "before", beforeRisk.Warnings)
	appendRiskWarnings(&result.Warnings, "after", afterRisk.Warnings)

	result.Truncated = beforePaths.Truncated || afterPaths.Truncated || beforeRisk.Truncated || afterRisk.Truncated
	result.Complete = before.Metadata.Complete && after.Metadata.Complete && beforeFindings.Complete && afterFindings.Complete &&
		beforePaths.Complete && afterPaths.Complete && beforeRisk.Complete && afterRisk.Complete && !result.Truncated
	if result.Truncated {
		result.Warnings = append(result.Warnings, Warning{Side: "both", Code: "Analysis.Truncated", Message: "attack-path or risk comparison reached a configured bound"})
	}
	result.Warnings = canonicalWarnings(result.Warnings)
	result.Summary = summarize(result)
	return result, nil
}

func analyzeFindings(ctx context.Context, value snapshot.Snapshot) (analysis.Result, error) {
	engine, err := analysis.New(value)
	if err != nil {
		return analysis.Result{}, err
	}
	return engine.Analyze(ctx)
}

func analyzePaths(ctx context.Context, value snapshot.Snapshot, query attackpath.Query) (attackpath.Result, error) {
	engine, err := attackpath.New(value)
	if err != nil {
		return attackpath.Result{}, err
	}
	return engine.Analyze(ctx, query)
}

func analyzeRisk(ctx context.Context, value snapshot.Snapshot, query risk.Query) (risk.Result, error) {
	engine, err := risk.New(value)
	if err != nil {
		return risk.Result{}, err
	}
	return engine.Analyze(ctx, query)
}

type objectRecord struct {
	category string
	ref      snapshot.ObjectRef
	digest   string
}

func compareObjects(before, after snapshot.Snapshot) ObjectDiff {
	left := snapshotObjects(before)
	right := snapshotObjects(after)
	result := ObjectDiff{Added: []ObjectSummary{}, Removed: []ObjectSummary{}, Modified: []ObjectModification{}}
	keys := unionKeys(left, right)
	for _, key := range keys {
		beforeValue, beforeOK := left[key]
		afterValue, afterOK := right[key]
		switch {
		case !beforeOK:
			result.Added = append(result.Added, ObjectSummary{Category: afterValue.category, Ref: afterValue.ref, Digest: afterValue.digest})
		case !afterOK:
			result.Removed = append(result.Removed, ObjectSummary{Category: beforeValue.category, Ref: beforeValue.ref, Digest: beforeValue.digest})
		case beforeValue.digest != afterValue.digest:
			result.Modified = append(result.Modified, ObjectModification{Category: afterValue.category, Ref: afterValue.ref, BeforeDigest: beforeValue.digest, AfterDigest: afterValue.digest})
		}
	}
	return result
}

func snapshotObjects(value snapshot.Snapshot) map[string]objectRecord {
	result := make(map[string]objectRecord)
	add := func(category string, ref snapshot.ObjectRef, object any) {
		key := category + "\x00" + refKey(ref)
		result[key] = objectRecord{category: category, ref: ref, digest: digest(object)}
	}
	for _, item := range value.APIResources {
		ref := snapshot.ObjectRef{APIGroup: item.APIGroup, Kind: "APIResource", Name: item.GroupVersion + "/" + item.Name}
		add("apiResource", ref, item)
	}
	for _, item := range value.Roles {
		add("role", item.Ref, item)
	}
	for _, item := range value.Bindings {
		add("binding", item.Ref, item)
	}
	for _, item := range value.ServiceAccounts {
		add("serviceAccount", item.Ref, item)
	}
	for _, item := range value.Workloads {
		add("workload", item.Ref, item)
	}
	for _, item := range value.Assets {
		add("asset", item.Ref, item)
	}
	for _, item := range value.SecurityControls {
		add("securityControl", item.Ref, item)
	}
	return result
}

func compareIdentities(before, after []snapshot.Identity) IdentityDiff {
	left := make(map[string]permission.Identity, len(before))
	right := make(map[string]permission.Identity, len(after))
	for _, item := range before {
		identity := permission.Identity{Kind: item.Kind, Namespace: item.Namespace, Name: item.Name}
		left[identityKey(identity)] = identity
	}
	for _, item := range after {
		identity := permission.Identity{Kind: item.Kind, Namespace: item.Namespace, Name: item.Name}
		right[identityKey(identity)] = identity
	}
	result := IdentityDiff{Added: []permission.Identity{}, Removed: []permission.Identity{}}
	for _, key := range unionKeys(left, right) {
		beforeValue, beforeOK := left[key]
		afterValue, afterOK := right[key]
		if !beforeOK {
			result.Added = append(result.Added, afterValue)
		} else if !afterOK {
			result.Removed = append(result.Removed, beforeValue)
		}
	}
	return result
}

type capabilityRecord struct {
	value  Capability
	grants []GrantSummary
}

func comparePermissions(ctx context.Context, before, after snapshot.Snapshot) ([]PermissionDiff, []DangerousCapabilityChange, []Warning, error) {
	beforeResolver, err := permission.New(before)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize before permission resolver: %w", err)
	}
	afterResolver, err := permission.New(after)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize after permission resolver: %w", err)
	}
	identities := make(map[string]permission.Identity)
	for _, item := range append(append([]snapshot.Identity(nil), before.Identities...), after.Identities...) {
		identity := permission.Identity{Kind: item.Kind, Namespace: item.Namespace, Name: item.Name}
		identities[identityKey(identity)] = identity
	}
	diffs := []PermissionDiff{}
	dangerous := []DangerousCapabilityChange{}
	warnings := []Warning{}
	for _, key := range sortedKeys(identities) {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		identity := identities[key]
		leftResult := beforeResolver.Permissions(identity, nil)
		rightResult := afterResolver.Permissions(identity, nil)
		appendPermissionWarnings(&warnings, "before", leftResult.Warnings)
		appendPermissionWarnings(&warnings, "after", rightResult.Warnings)
		left := capabilityRecords(leftResult.Capabilities)
		right := capabilityRecords(rightResult.Capabilities)
		current := PermissionDiff{Identity: identity, Added: []Capability{}, Removed: []Capability{}, ChangedGrants: []GrantChange{}}
		for _, capabilityKey := range unionKeys(left, right) {
			beforeValue, beforeOK := left[capabilityKey]
			afterValue, afterOK := right[capabilityKey]
			switch {
			case !beforeOK:
				current.Added = append(current.Added, afterValue.value)
				if category := dangerousCategory(afterValue.value); category != "" {
					dangerous = append(dangerous, DangerousCapabilityChange{Direction: Added, Category: category, Identity: identity, Capability: afterValue.value})
				}
			case !afterOK:
				current.Removed = append(current.Removed, beforeValue.value)
				if category := dangerousCategory(beforeValue.value); category != "" {
					dangerous = append(dangerous, DangerousCapabilityChange{Direction: Removed, Category: category, Identity: identity, Capability: beforeValue.value})
				}
			default:
				added, removed := compareGrants(beforeValue.grants, afterValue.grants)
				if len(added) > 0 || len(removed) > 0 {
					current.ChangedGrants = append(current.ChangedGrants, GrantChange{Capability: afterValue.value, Added: added, Removed: removed})
				}
			}
		}
		if len(current.Added) > 0 || len(current.Removed) > 0 || len(current.ChangedGrants) > 0 {
			diffs = append(diffs, current)
		}
	}
	sort.Slice(dangerous, func(i, j int) bool { return dangerousKey(dangerous[i]) < dangerousKey(dangerous[j]) })
	return diffs, dangerous, canonicalWarnings(warnings), nil
}

func capabilityRecords(values []permission.Capability) map[string]capabilityRecord {
	result := make(map[string]capabilityRecord, len(values))
	for _, item := range values {
		value := Capability{
			Verb: item.Verb, APIGroup: item.APIGroup, Resource: item.Resource, Subresource: item.Subresource,
			ResourceNames: append([]string{}, item.ResourceNames...), NonResourceURL: item.NonResourceURL,
			Scope: item.Scope, Namespace: item.Namespace,
		}
		grants := make([]GrantSummary, 0, len(item.Grants))
		for _, grant := range item.Grants {
			grants = append(grants, GrantSummary{ID: grant.ID, BindingRef: grant.BindingRef, RoleRef: grant.RoleRef})
		}
		sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
		result[capabilityKey(value)] = capabilityRecord{value: value, grants: grants}
	}
	return result
}

func compareGrants(before, after []GrantSummary) ([]GrantSummary, []GrantSummary) {
	left := make(map[string]GrantSummary, len(before))
	right := make(map[string]GrantSummary, len(after))
	for _, item := range before {
		left[item.ID] = item
	}
	for _, item := range after {
		right[item.ID] = item
	}
	added := []GrantSummary{}
	removed := []GrantSummary{}
	for _, key := range unionKeys(left, right) {
		beforeValue, beforeOK := left[key]
		afterValue, afterOK := right[key]
		if !beforeOK {
			added = append(added, afterValue)
		} else if !afterOK {
			removed = append(removed, beforeValue)
		}
	}
	return added, removed
}

func dangerousCategory(value Capability) string {
	if value.Verb == "*" || value.APIGroup == "*" || value.Resource == "*" || value.NonResourceURL == "*" {
		return "WILDCARD"
	}
	if value.Verb == "impersonate" {
		return "IMPERSONATION"
	}
	if value.Verb == "bind" || value.Verb == "escalate" {
		return "RBAC_CONTROL"
	}
	if value.Resource == "serviceaccounts" && value.Subresource == "token" && isVerb(value.Verb, "create") {
		return "SERVICE_ACCOUNT_TOKEN"
	}
	if value.Resource == "secrets" && isReadVerb(value.Verb) {
		return "SECRET_ACCESS"
	}
	if isMutationVerb(value.Verb) && isWorkloadResource(value.Resource) {
		return "WORKLOAD_MUTATION"
	}
	if isMutationVerb(value.Verb) && (value.Resource == "roles" || value.Resource == "clusterroles" || value.Resource == "rolebindings" || value.Resource == "clusterrolebindings") {
		return "RBAC_CONTROL"
	}
	return ""
}

func isVerb(actual, wanted string) bool { return actual == wanted || actual == "*" }

func isReadVerb(value string) bool {
	return value == "get" || value == "list" || value == "watch" || value == "*"
}

func isMutationVerb(value string) bool {
	return value == "create" || value == "update" || value == "patch" || value == "delete" || value == "deletecollection" || value == "*"
}

func isWorkloadResource(value string) bool {
	switch value {
	case "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs":
		return true
	default:
		return false
	}
}

func compareFindings(before, after analysis.Result) FindingDiff {
	left := make(map[string]FindingSummary, len(before.Findings))
	right := make(map[string]FindingSummary, len(after.Findings))
	for _, item := range before.Findings {
		left[item.ID] = findingSummary(item)
	}
	for _, item := range after.Findings {
		right[item.ID] = findingSummary(item)
	}
	result := FindingDiff{Added: []FindingSummary{}, Removed: []FindingSummary{}}
	for _, key := range unionKeys(left, right) {
		beforeValue, beforeOK := left[key]
		afterValue, afterOK := right[key]
		if !beforeOK {
			result.Added = append(result.Added, afterValue)
		} else if !afterOK {
			result.Removed = append(result.Removed, beforeValue)
		}
	}
	return result
}

func findingSummary(value analysis.Finding) FindingSummary {
	return FindingSummary{ID: value.ID, RuleID: value.RuleID, Title: value.Title, Severity: value.Severity, RiskScore: value.RiskScore, Confidence: value.Confidence}
}

func comparePaths(before, after []attackpath.Path) AttackPathDiff {
	left := semanticPaths(before)
	right := semanticPaths(after)
	result := AttackPathDiff{Added: []PathSummary{}, Removed: []PathSummary{}, ChangedState: []PathStateChange{}}
	for _, key := range unionKeys(left, right) {
		beforeValue, beforeOK := left[key]
		afterValue, afterOK := right[key]
		switch {
		case !beforeOK:
			result.Added = append(result.Added, afterValue)
		case !afterOK:
			result.Removed = append(result.Removed, beforeValue)
		case beforeValue.Confidence != afterValue.Confidence || beforeValue.Blocked != afterValue.Blocked || beforeValue.Cost != afterValue.Cost:
			result.ChangedState = append(result.ChangedState, PathStateChange{Key: key, Before: beforeValue, After: afterValue})
		}
	}
	return result
}

func semanticPaths(values []attackpath.Path) map[string]PathSummary {
	result := make(map[string]PathSummary)
	for _, item := range values {
		summary := PathSummary{ID: item.ID, TemplateID: item.TemplateID, Title: item.Title, Source: item.Source, Target: item.Target, Confidence: item.Confidence, Blocked: item.Blocked, Cost: item.Cost}
		key := pathKey(summary)
		current, exists := result[key]
		if !exists || pathSummaryOrder(summary) < pathSummaryOrder(current) {
			result[key] = summary
		}
	}
	return result
}

func compareControls(before, after []snapshot.SecurityControl) ControlDiff {
	left := make(map[string]snapshot.SecurityControl, len(before))
	right := make(map[string]snapshot.SecurityControl, len(after))
	for _, item := range before {
		left[controlKey(item)] = item
	}
	for _, item := range after {
		right[controlKey(item)] = item
	}
	result := ControlDiff{Added: []snapshot.SecurityControl{}, Removed: []snapshot.SecurityControl{}, Modified: []ControlChange{}}
	for _, key := range unionKeys(left, right) {
		beforeValue, beforeOK := left[key]
		afterValue, afterOK := right[key]
		switch {
		case !beforeOK:
			result.Added = append(result.Added, afterValue)
		case !afterOK:
			result.Removed = append(result.Removed, beforeValue)
		case digest(beforeValue) != digest(afterValue):
			result.Modified = append(result.Modified, ControlChange{Ref: afterValue.Ref, Before: beforeValue, After: afterValue})
		}
	}
	return result
}

func compareRisk(before, after risk.Result) RiskDiff {
	result := RiskDiff{
		Cluster:    scoreDelta(before.Cluster.Key, before.Cluster, after.Cluster),
		Identities: compareAggregateScores(before.Identities, after.Identities),
		Namespaces: compareAggregateScores(before.Namespaces, after.Namespaces),
	}
	return result
}

func compareAggregateScores(before, after []risk.AggregateScore) []ScoreDelta {
	left := make(map[string]risk.AggregateScore, len(before))
	right := make(map[string]risk.AggregateScore, len(after))
	for _, item := range before {
		left[item.Key] = item
	}
	for _, item := range after {
		right[item.Key] = item
	}
	result := []ScoreDelta{}
	for _, key := range unionKeys(left, right) {
		beforeValue := left[key]
		afterValue := right[key]
		if beforeValue.Score != afterValue.Score || beforeValue.Severity != afterValue.Severity {
			result = append(result, scoreDelta(key, beforeValue, afterValue))
		}
	}
	return result
}

func scoreDelta(key string, before, after risk.AggregateScore) ScoreDelta {
	beforeSeverity := before.Severity
	afterSeverity := after.Severity
	if beforeSeverity == "" {
		beforeSeverity = risk.SeverityInfo
	}
	if afterSeverity == "" {
		afterSeverity = risk.SeverityInfo
	}
	return ScoreDelta{Key: key, Before: before.Score, After: after.Score, Delta: after.Score - before.Score, BeforeSeverity: beforeSeverity, AfterSeverity: afterSeverity}
}

func summarize(value Result) Summary {
	result := Summary{
		ObjectsAdded: len(value.Objects.Added), ObjectsRemoved: len(value.Objects.Removed), ObjectsModified: len(value.Objects.Modified),
		IdentitiesAdded: len(value.Identities.Added), IdentitiesRemoved: len(value.Identities.Removed),
		DangerousCapabilitiesNew: countDangerous(value.DangerousCapabilities, Added),
		FindingsAdded:            len(value.Findings.Added), FindingsRemoved: len(value.Findings.Removed),
		AttackPathsAdded: len(value.AttackPaths.Added), AttackPathsRemoved: len(value.AttackPaths.Removed), AttackPathStatesChanged: len(value.AttackPaths.ChangedState),
		ControlsChanged:  len(value.Controls.Added) + len(value.Controls.Removed) + len(value.Controls.Modified),
		ClusterRiskDelta: value.Risk.Cluster.Delta,
	}
	for _, item := range value.Permissions {
		result.PermissionsAdded += len(item.Added)
		result.PermissionsRemoved += len(item.Removed)
		result.PermissionGrantsChanged += len(item.ChangedGrants)
	}
	return result
}

func countDangerous(values []DangerousCapabilityChange, direction Direction) int {
	count := 0
	for _, value := range values {
		if value.Direction == direction {
			count++
		}
	}
	return count
}

func appendPermissionWarnings(target *[]Warning, side string, values []permission.Warning) {
	for _, value := range values {
		*target = append(*target, Warning{Side: side, Code: value.Code, Message: value.Message})
	}
}

func appendFindingWarnings(target *[]Warning, side string, values []analysis.Warning) {
	for _, value := range values {
		*target = append(*target, Warning{Side: side, Code: value.Code, Message: value.Message})
	}
}

func appendPathWarnings(target *[]Warning, side string, values []attackpath.Warning) {
	for _, value := range values {
		*target = append(*target, Warning{Side: side, Code: value.Code, Message: value.Message})
	}
}

func appendRiskWarnings(target *[]Warning, side string, values []risk.Warning) {
	for _, value := range values {
		*target = append(*target, Warning{Side: side, Code: value.Code, Message: value.Message})
	}
}

func canonicalWarnings(values []Warning) []Warning {
	sort.Slice(values, func(i, j int) bool { return warningKey(values[i]) < warningKey(values[j]) })
	result := make([]Warning, 0, len(values))
	for _, item := range values {
		if len(result) == 0 || warningKey(result[len(result)-1]) != warningKey(item) {
			result = append(result, item)
		}
	}
	return result
}

func warningKey(value Warning) string {
	return value.Side + "\x00" + value.Code + "\x00" + value.Message
}

func dangerousKey(value DangerousCapabilityChange) string {
	return string(value.Direction) + "\x00" + value.Category + "\x00" + identityKey(value.Identity) + "\x00" + capabilityKey(value.Capability)
}

func capabilityKey(value Capability) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func pathKey(value PathSummary) string {
	return identityKey(value.Source) + "\x00" + value.TemplateID + "\x00" + value.Target.Key
}

func pathSummaryOrder(value PathSummary) string {
	return fmt.Sprintf("%08d\x00%s", value.Cost, value.ID)
}

func controlKey(value snapshot.SecurityControl) string {
	return refKey(value.Ref) + "\x00" + value.ControlType
}

func refKey(value snapshot.ObjectRef) string {
	return value.APIGroup + "\x00" + value.Kind + "\x00" + value.Namespace + "\x00" + value.Name
}

func identityKey(value permission.Identity) string {
	return string(value.Kind) + "\x00" + value.Namespace + "\x00" + value.Name
}

func digest(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:12])
}

func unionKeys[T any](left, right map[string]T) []string {
	values := make(map[string]struct{}, len(left)+len(right))
	for key := range left {
		values[key] = struct{}{}
	}
	for key := range right {
		values[key] = struct{}{}
	}
	return sortedKeys(values)
}

func sortedKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
