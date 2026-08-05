package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	semanticdiff "github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	defaultMaxCandidates = 250
	defaultMaxPaths      = 10000
	defaultMaxExpanded   = 100000
)

// Generate creates, virtually applies, and ranks remediation candidates.
func Generate(ctx context.Context, input snapshot.Snapshot, options Options) (Result, error) {
	base, err := snapshot.Canonicalize(input)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize remediation input: %w", err)
	}
	options = normalizeOptions(options)
	pathEngine, err := attackpath.New(base)
	if err != nil {
		return Result{}, fmt.Errorf("initialize remediation attack paths: %w", err)
	}
	pathQuery := attackpath.Query{From: options.Identity, Namespace: options.Namespace, Top: options.MaxPaths, MaxExpanded: options.MaxExpanded}
	paths, err := pathEngine.Analyze(ctx, pathQuery)
	if err != nil {
		return Result{}, fmt.Errorf("analyze remediation paths: %w", err)
	}
	riskEngine, err := risk.New(base)
	if err != nil {
		return Result{}, fmt.Errorf("initialize remediation risk: %w", err)
	}
	baseline, err := riskEngine.Analyze(ctx, risk.Query{From: options.Identity, Namespace: options.Namespace, MaxPaths: options.MaxPaths, MaxExpanded: options.MaxExpanded})
	if err != nil {
		return Result{}, fmt.Errorf("analyze remediation baseline risk: %w", err)
	}

	raw := generateCandidates(paths.Paths)
	generated := len(raw)
	truncated := paths.Truncated || baseline.Truncated
	if len(raw) > options.MaxCandidates {
		raw = raw[:options.MaxCandidates]
		truncated = true
	}
	severityByPath := make(map[string]risk.Severity, len(baseline.PathScores))
	for _, score := range baseline.PathScores {
		severityByPath[score.PathID] = score.Severity
	}

	evaluated := make([]Candidate, 0, len(raw))
	for _, candidate := range raw {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		simulated, err := applyCandidate(base, candidate)
		if err != nil {
			return Result{}, fmt.Errorf("simulate remediation %s: %w", candidate.ID, err)
		}
		comparison, err := semanticdiff.Compare(ctx, base, simulated, semanticdiff.Options{MaxPaths: options.MaxPaths, MaxExpanded: options.MaxExpanded})
		if err != nil {
			return Result{}, fmt.Errorf("measure remediation %s: %w", candidate.ID, err)
		}
		candidate = measureCandidate(candidate, comparison, severityByPath, len(paths.Paths), base.Metadata.Complete, options.IncludeDiff)
		if comparison.Truncated {
			truncated = true
		}
		evaluated = append(evaluated, candidate)
	}
	paretoRank(evaluated)
	sortCandidates(evaluated)
	for index := range evaluated {
		evaluated[index].Ranking.Rank = index + 1
	}
	summary := summarize(evaluated, generated, baseline.Cluster.Score)
	visible := evaluated
	if !options.IncludeDominated {
		visible = make([]Candidate, 0, len(evaluated))
		for _, candidate := range evaluated {
			if candidate.Disposition != DispositionDominated {
				visible = append(visible, candidate)
			}
		}
	}

	warnings := remediationWarnings(base, paths, baseline, truncated, generated, len(raw))
	complete := base.Metadata.Complete && paths.Complete && baseline.Complete && !truncated
	result := Result{
		SchemaVersion: ResultSchemaVersion, ModelVersion: ModelVersion, Complete: complete, Truncated: truncated,
		Candidates: visible, Warnings: warnings, BaselineRisk: baseline.Cluster, Summary: summary,
	}
	return result, nil
}

func normalizeOptions(value Options) Options {
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

func generateCandidates(paths []attackpath.Path) []Candidate {
	byKey := make(map[string]Candidate)
	for _, path := range paths {
		if path.Blocked {
			continue
		}
		for _, step := range path.Steps {
			var stepPermission *attackpath.PermissionEvidence
			for _, evidence := range step.Evidence {
				if evidence.Permission != nil {
					stepPermission = evidence.Permission
					break
				}
			}
			for _, evidence := range step.Evidence {
				if evidence.Grant == nil {
					continue
				}
				grant := evidence.Grant
				change := Change{Kind: KindRemoveSubject, Ref: grant.BindingRef, Subject: cloneSubject(grant.Subject)}
				key := changeKey(change)
				candidate := candidateForChange(change, key, "Remove subject from binding", "Remove only the observed subject from the binding; delete the binding virtually when it becomes empty.")
				mergeCandidate(byKey, key, candidate, path)

				if stepPermission != nil && grant.PolicyRuleID != "" && stepPermission.Verb != "*" && !contains(grant.OriginalRule.Verbs, "*") {
					change = Change{Kind: KindNarrowRule, Ref: grant.SourceRoleRef, PolicyRuleID: grant.PolicyRuleID, Verb: stepPermission.Verb, Before: stepPermission.Verb, After: "removed"}
					key = changeKey(change)
					candidate = candidateForChange(change, key, "Narrow RBAC rule", fmt.Sprintf("Remove verb %q from the exact source rule and measure every permission lost by that edit.", stepPermission.Verb))
					mergeCandidate(byKey, key, candidate, path)
				}
			}
		}
		if path.Target.Type == attackpath.TargetHostEscape && path.Target.Namespace != "" {
			change := Change{Kind: KindEnforcePSA, Ref: snapshot.ObjectRef{Kind: "Namespace", Name: path.Target.Namespace}, Namespace: path.Target.Namespace, Before: "observed policy", After: "restricted"}
			key := changeKey(change)
			candidate := candidateForChange(change, key, "Enforce restricted Pod Security Admission", "Virtually set the namespace Pod Security Admission enforce level to restricted.")
			mergeCandidate(byKey, key, candidate, path)
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Candidate, 0, len(keys))
	for _, key := range keys {
		candidate := byKey[key]
		candidate.PathIDs = sortedUnique(candidate.PathIDs)
		candidate.Targets = sortedTargets(candidate.Targets)
		result = append(result, candidate)
	}
	return result
}

func candidateForChange(change Change, key, title, description string) Candidate {
	return Candidate{ID: stableID("remediation", key), Kind: change.Kind, Title: title, Description: description, Change: change, PathIDs: []string{}, Targets: []attackpath.PrivilegeTargetType{}, actionKey: key}
}

func mergeCandidate(values map[string]Candidate, key string, candidate Candidate, path attackpath.Path) {
	current, ok := values[key]
	if !ok {
		current = candidate
	}
	current.PathIDs = append(current.PathIDs, path.ID)
	current.Targets = append(current.Targets, path.Target.Type)
	values[key] = current
}

func applyCandidate(base snapshot.Snapshot, candidate Candidate) (snapshot.Snapshot, error) {
	// Canonicalize is also the package's deep-copy boundary. Candidate
	// simulation must never mutate the shared baseline through slice backing
	// arrays while editing nested roles or bindings.
	value, err := snapshot.Canonicalize(base)
	if err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("clone remediation baseline: %w", err)
	}
	switch candidate.Change.Kind {
	case KindRemoveSubject:
		if candidate.Change.Subject == nil {
			return snapshot.Snapshot{}, fmt.Errorf("remove-subject candidate has no subject")
		}
		found := false
		bindings := make([]snapshot.Binding, 0, len(value.Bindings))
		for _, binding := range value.Bindings {
			if sameRef(binding.Ref, candidate.Change.Ref) {
				found = true
				subjects := make([]snapshot.Subject, 0, len(binding.Subjects))
				for _, subject := range binding.Subjects {
					if !sameSubject(subject, *candidate.Change.Subject) {
						subjects = append(subjects, subject)
					}
				}
				binding.Subjects = subjects
				if len(subjects) == 0 {
					continue
				}
			}
			bindings = append(bindings, binding)
		}
		if !found {
			return snapshot.Snapshot{}, fmt.Errorf("binding %s/%s not found", candidate.Change.Ref.Namespace, candidate.Change.Ref.Name)
		}
		value.Bindings = bindings
	case KindNarrowRule:
		found := false
		for roleIndex := range value.Roles {
			role := &value.Roles[roleIndex]
			if !sameRef(role.Ref, candidate.Change.Ref) {
				continue
			}
			rules := make([]snapshot.PolicyRule, 0, len(role.Rules))
			for _, rule := range role.Rules {
				if rule.ID == candidate.Change.PolicyRuleID {
					found = true
					rule.Verbs = removeString(rule.Verbs, candidate.Change.Verb)
					if len(rule.Verbs) == 0 {
						continue
					}
				}
				rules = append(rules, rule)
			}
			role.Rules = rules
		}
		if !found {
			return snapshot.Snapshot{}, fmt.Errorf("policy rule %s not found", candidate.Change.PolicyRuleID)
		}
	case KindEnforcePSA:
		control := snapshot.SecurityControl{
			Ref: snapshot.ObjectRef{Kind: "Namespace", Name: candidate.Change.Namespace}, ControlType: "PodSecurityAdmission", Mode: "restricted",
			Details: []snapshot.KeyValue{{Key: "pod-security.kubernetes.io/enforce", Value: "restricted"}},
		}
		replaced := false
		for index := range value.SecurityControls {
			if value.SecurityControls[index].ControlType == control.ControlType && sameRef(value.SecurityControls[index].Ref, control.Ref) {
				value.SecurityControls[index] = control
				replaced = true
			}
		}
		if !replaced {
			value.SecurityControls = append(value.SecurityControls, control)
		}
	default:
		return snapshot.Snapshot{}, fmt.Errorf("unsupported remediation kind %q", candidate.Change.Kind)
	}
	value.Identities = nil
	return snapshot.Canonicalize(value)
}

func measureCandidate(candidate Candidate, comparison semanticdiff.Result, severityByPath map[string]risk.Severity, baselinePathCount int, baseComplete, includeDiff bool) Candidate {
	impact := Impact{RemovedPathIDs: []string{}, BlockedPathIDs: []string{}, LostCapabilities: []LostCapability{}, AffectedIdentities: []permission.Identity{}, Risk: comparison.Risk}
	benefit := SecurityBenefit{}
	for _, path := range comparison.AttackPaths.Removed {
		impact.RemovedPathIDs = append(impact.RemovedPathIDs, path.ID)
		switch severityByPath[path.ID] {
		case risk.SeverityCritical:
			benefit.RemovedCriticalPaths++
		case risk.SeverityHigh:
			benefit.RemovedHighPaths++
		case risk.SeverityMedium:
			benefit.RemovedMediumPaths++
		}
	}
	for _, change := range comparison.AttackPaths.ChangedState {
		if !change.Before.Blocked && change.After.Blocked {
			impact.BlockedPathIDs = append(impact.BlockedPathIDs, change.Before.ID)
			benefit.BlockedPaths++
		}
	}
	identitySet := map[string]permission.Identity{}
	for _, permissionDiff := range comparison.Permissions {
		for _, capability := range permissionDiff.Removed {
			impact.LostCapabilities = append(impact.LostCapabilities, LostCapability{Identity: permissionDiff.Identity, Capability: capability})
			identitySet[permissionDiff.Identity.String()] = permissionDiff.Identity
		}
		impact.UnresolvedGrantChanges += len(permissionDiff.ChangedGrants)
	}
	for _, identity := range comparison.Identities.Removed {
		identitySet[identity.String()] = identity
	}
	for _, identity := range identitySet {
		impact.AffectedIdentities = append(impact.AffectedIdentities, identity)
	}
	sort.Slice(impact.AffectedIdentities, func(i, j int) bool {
		return impact.AffectedIdentities[i].String() < impact.AffectedIdentities[j].String()
	})
	impact.RemovedPathIDs = sortedUnique(impact.RemovedPathIDs)
	impact.BlockedPathIDs = sortedUnique(impact.BlockedPathIDs)
	impact.RemainingAttackPaths = baselinePathCount - len(comparison.AttackPaths.Removed) + len(comparison.AttackPaths.Added)
	if impact.RemainingAttackPaths < 0 {
		impact.RemainingAttackPaths = 0
	}
	benefit.ClusterRiskReduction = positive(-comparison.Risk.Cluster.Delta)
	benefit.ScopedRiskReduction = scopedRiskReduction(comparison.Risk)
	benefit.Total = benefit.RemovedCriticalPaths*1200 + benefit.RemovedHighPaths*700 + benefit.RemovedMediumPaths*300 + benefit.BlockedPaths*900 + benefit.ClusterRiskReduction*20 + benefit.ScopedRiskReduction*5
	cost := OperationalCost{LostCapabilities: len(impact.LostCapabilities), AffectedIdentities: len(impact.AffectedIdentities), OperationalComplexity: complexity(candidate.Kind)}
	if !baseComplete || !comparison.Complete || comparison.Truncated {
		cost.UncertaintyPenalty = 500
	}
	cost.Total = cost.LostCapabilities*100 + cost.AffectedIdentities*200 + cost.OperationalComplexity*100 + cost.UncertaintyPenalty
	denominator := cost.Total
	if denominator < 100 {
		denominator = 100
	}
	candidate.Benefit, candidate.Cost, candidate.Impact = benefit, cost, impact
	candidate.Ranking.BenefitCostBasis = benefit.Total * 10000 / denominator
	if includeDiff {
		candidate.Diff = &comparison
	}
	if benefit.Total == 0 {
		candidate.Disposition = DispositionIneffective
		candidate.Reason = "virtual application produced no measurable attack-path or risk reduction"
		if impact.UnresolvedGrantChanges > 0 {
			candidate.Reason = "a redundant grant changed, but effective access and modeled risk remained"
		}
	} else {
		candidate.Disposition = DispositionRecommended
		candidate.Reason = "virtual application produced measurable security improvement"
	}
	return candidate
}

func paretoRank(values []Candidate) {
	for index := range values {
		if values[index].Disposition == DispositionIneffective {
			continue
		}
		dominated := false
		for other := range values {
			if index == other || values[other].Disposition == DispositionIneffective {
				continue
			}
			betterOrEqual := values[other].Benefit.Total >= values[index].Benefit.Total && values[other].Cost.Total <= values[index].Cost.Total
			strict := values[other].Benefit.Total > values[index].Benefit.Total || values[other].Cost.Total < values[index].Cost.Total
			if betterOrEqual && strict {
				dominated = true
				break
			}
		}
		values[index].Ranking.ParetoOptimal = !dominated
		if dominated {
			values[index].Disposition = DispositionDominated
			values[index].Reason = "another simulated candidate provides at least as much benefit at lower or equal cost"
		}
	}
}

func sortCandidates(values []Candidate) {
	order := func(value Disposition) int {
		switch value {
		case DispositionRecommended:
			return 0
		case DispositionDominated:
			return 1
		default:
			return 2
		}
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if order(left.Disposition) != order(right.Disposition) {
			return order(left.Disposition) < order(right.Disposition)
		}
		if left.Ranking.BenefitCostBasis != right.Ranking.BenefitCostBasis {
			return left.Ranking.BenefitCostBasis > right.Ranking.BenefitCostBasis
		}
		if left.Benefit.Total != right.Benefit.Total {
			return left.Benefit.Total > right.Benefit.Total
		}
		if left.Cost.Total != right.Cost.Total {
			return left.Cost.Total < right.Cost.Total
		}
		return left.ID < right.ID
	})
}

func summarize(values []Candidate, generated, baseline int) Summary {
	result := Summary{Generated: generated, Evaluated: len(values), BestRiskBefore: baseline, BestRiskAfter: baseline}
	for _, value := range values {
		switch value.Disposition {
		case DispositionRecommended:
			result.Recommended++
		case DispositionDominated:
			result.Dominated++
		case DispositionIneffective:
			result.Ineffective++
		}
		if value.Benefit.Total > 0 && value.Impact.Risk.Cluster.After < result.BestRiskAfter {
			result.BestRiskAfter = value.Impact.Risk.Cluster.After
		}
	}
	return result
}

func remediationWarnings(base snapshot.Snapshot, paths attackpath.Result, baseline risk.Result, truncated bool, generated, evaluated int) []Warning {
	values := []Warning{}
	if !base.Metadata.Complete {
		values = append(values, Warning{Code: "Collection.Incomplete", Message: "remediation conclusions are bounded by incomplete snapshot collection"})
	}
	for _, warning := range paths.Warnings {
		values = append(values, Warning{Code: "AttackPath." + warning.Code, Message: warning.Message})
	}
	for _, warning := range baseline.Warnings {
		values = append(values, Warning{Code: "Risk." + warning.Code, Message: warning.Message})
	}
	if truncated {
		values = append(values, Warning{Code: "Analysis.Truncated", Message: "configured candidate or analysis bound was reached"})
	}
	if generated > evaluated {
		values = append(values, Warning{Code: "Candidates.Truncated", Message: fmt.Sprintf("evaluated %d of %d generated candidates", evaluated, generated)})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Code+values[i].Message < values[j].Code+values[j].Message })
	return values
}

func scopedRiskReduction(value semanticdiff.RiskDiff) int {
	total := 0
	for _, item := range value.Identities {
		total += positive(-item.Delta)
	}
	for _, item := range value.Namespaces {
		total += positive(-item.Delta)
	}
	return total
}

func complexity(kind Kind) int {
	switch kind {
	case KindRemoveSubject:
		return 2
	case KindNarrowRule:
		return 3
	case KindEnforcePSA:
		return 4
	default:
		return 5
	}
}

func changeKey(value Change) string {
	subject := ""
	if value.Subject != nil {
		subject = string(value.Subject.Kind) + ":" + value.Subject.Namespace + ":" + value.Subject.Name
	}
	return strings.Join([]string{string(value.Kind), refKey(value.Ref), subject, value.PolicyRuleID, value.Verb, value.Namespace}, "|")
}

func stableID(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + ":" + hex.EncodeToString(digest[:12])
}

func refKey(value snapshot.ObjectRef) string {
	return value.APIGroup + "/" + value.Kind + "/" + value.Namespace + "/" + value.Name
}

func sameRef(left, right snapshot.ObjectRef) bool {
	return left.APIGroup == right.APIGroup && left.Kind == right.Kind && left.Namespace == right.Namespace && left.Name == right.Name
}

func sameSubject(left, right snapshot.Subject) bool {
	return left.Kind == right.Kind && left.APIGroup == right.APIGroup && left.Namespace == right.Namespace && left.Name == right.Name
}

func cloneSubject(value snapshot.Subject) *snapshot.Subject { result := value; return &result }

func removeString(values []string, target string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedTargets(values []attackpath.PrivilegeTargetType) []attackpath.PrivilegeTargetType {
	set := make(map[attackpath.PrivilegeTargetType]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]attackpath.PrivilegeTargetType, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func positive(value int) int {
	if value > 0 {
		return value
	}
	return 0
}
