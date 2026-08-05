package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const (
	weightDivisor             = 100
	basisPointsDivisor        = 10000
	blockingMitigationBPS     = 9000
	potentialMitigationBPS    = 1000
	maxPotentialMitigationBPS = 3000
	additionalRiskRatePercent = 15
)

var factorWeights = map[FactorName]int{
	FactorImpact: 30, FactorExploitability: 22, FactorBlastRadius: 18,
	FactorExposure: 10, FactorPathQuality: 10, FactorConfidence: 10,
}

func scorePath(path attackpath.Path, input snapshot.Snapshot, includePath bool) PathScore {
	factors := []Factor{
		newFactor(FactorImpact, clamp(path.Target.PrivilegeGain), "typed privilege target privilegeGain"),
		newFactor(FactorExploitability, exploitability(path), "modeled technique cost excluding mitigation and uncertainty"),
		newFactor(FactorBlastRadius, clamp(path.Target.BlastRadius), "typed privilege target blastRadius"),
		newFactor(FactorExposure, exposure(path, input), exposureSource(path, input)),
		newFactor(FactorPathQuality, pathQuality(path), "evidence completeness and explicit prerequisites"),
		newFactor(FactorConfidence, confidenceValue(path.Confidence), "confidence mapping in risk model "+ModelVersion),
	}
	weightedTotal := 0
	for _, factor := range factors {
		weightedTotal += factor.Contribution
	}
	scopeBPS := scopeFactor(path)
	mitigation := mitigationFor(path)
	numerator := int64(weightedTotal) * int64(scopeBPS) * int64(basisPointsDivisor-mitigation.EffectBasisPts)
	denominator := int64(weightDivisor * basisPointsDivisor * basisPointsDivisor)
	score := clamp(roundDivide(numerator, denominator))
	namespaces := pathNamespaces(path, input)
	result := PathScore{
		ID: stableID("risk", ModelVersion+"\x00"+path.ID), PathID: path.ID, TemplateID: path.TemplateID,
		Title: path.Title, Source: path.Source, Target: path.Target, Confidence: path.Confidence,
		Blocked: path.Blocked, Namespaces: namespaces, Factors: factors, ScopeFactorBPS: scopeBPS,
		Mitigation: mitigation, Score: score, Severity: severity(score),
		RiskUnit: riskUnit(path),
		Formula: Formula{
			Expression:    "round(weightedTotal/100 * scopeBPS/10000 * (1-mitigationBPS/10000))",
			WeightedTotal: weightedTotal, WeightDivisor: weightDivisor, ScopeFactorBasisPts: scopeBPS,
			MitigationBasisPts: mitigation.EffectBasisPts, Numerator: numerator, Denominator: denominator,
		},
	}
	if includePath {
		copyPath := path
		result.Path = &copyPath
	}
	return result
}

func newFactor(name FactorName, value int, source string) Factor {
	weight := factorWeights[name]
	return Factor{Name: name, Value: value, Weight: weight, Contribution: value * weight, Source: source}
}

func exploitability(path attackpath.Path) int {
	cost := 0
	if len(path.Steps) > 0 {
		value := path.Steps[0].Cost
		cost = value.BaseTechnique + value.PrerequisitePenalty + value.OperationalComplexity
	}
	return clamp(100 - cost*8)
}

func exposure(path attackpath.Path, input snapshot.Snapshot) int {
	if path.Source.Kind != snapshot.IdentityServiceAccount {
		if path.Source.Kind == snapshot.IdentityGroup {
			return 70
		}
		return 60
	}
	count := workloadCount(path, input)
	return clamp(45 + smaller(count*10, 35))
}

func exposureSource(path attackpath.Path, input snapshot.Snapshot) string {
	if path.Source.Kind == snapshot.IdentityServiceAccount {
		return fmt.Sprintf("ServiceAccount usage by %d observed workload(s)", workloadCount(path, input))
	}
	return "directly bound " + strings.ToLower(string(path.Source.Kind)) + " identity"
}

func workloadCount(path attackpath.Path, input snapshot.Snapshot) int {
	count := 0
	for _, workload := range input.Workloads {
		if workload.Ref.Namespace == path.Source.Namespace && workload.ServiceAccountName == path.Source.Name {
			count++
		}
	}
	return count
}

func pathQuality(path attackpath.Path) int {
	value := 50
	if len(path.Steps) > 0 {
		for _, evidence := range path.Steps[0].Evidence {
			if evidence.Permission != nil {
				value += 15
			}
			if evidence.Grant != nil {
				value += 20
			}
			if evidence.Ref != nil {
				value += 10
			}
		}
		for _, prerequisite := range path.Steps[0].Prerequisites {
			switch prerequisite.State {
			case attackpath.PrerequisiteRequired:
				value -= 15
			case attackpath.PrerequisiteUnknown:
				value -= 25
			}
		}
	}
	return clamp(value)
}

func confidenceValue(value attackpath.Confidence) int {
	switch value {
	case attackpath.ConfidenceConfirmed:
		return 100
	case attackpath.ConfidenceLikely:
		return 85
	case attackpath.ConfidenceConditional:
		return 60
	case attackpath.ConfidenceUnknown:
		return 35
	case attackpath.ConfidenceBlocked:
		return 20
	default:
		return 0
	}
}

func scopeFactor(path attackpath.Path) int {
	if path.Target.Namespace == "" && clusterImpact(path.Target.Type) {
		return 11500
	}
	if path.Target.Namespace != "" {
		return 10000
	}
	if path.Source.Namespace != "" {
		return 9500
	}
	return 8500
}

func clusterImpact(value attackpath.PrivilegeTargetType) bool {
	switch value {
	case attackpath.TargetClusterAdmin, attackpath.TargetSystemMasters, attackpath.TargetRBACControl,
		attackpath.TargetAdmissionControl, attackpath.TargetNodeControl, attackpath.TargetHostEscape,
		attackpath.TargetCrossNamespaceControl, attackpath.TargetPersistence:
		return true
	default:
		return false
	}
}

func mitigationFor(path attackpath.Path) Mitigation {
	result := Mitigation{Reasons: []string{}}
	seen := make(map[string]struct{})
	for _, step := range path.Steps {
		for _, control := range step.MitigatingControls {
			if _, ok := seen[control.ID]; ok {
				continue
			}
			seen[control.ID] = struct{}{}
			switch control.State {
			case attackpath.MitigationBlocking:
				result.Blocking++
			case attackpath.MitigationPotential:
				result.Potential++
			default:
				result.Observed++
			}
			result.Reasons = append(result.Reasons, control.Reason)
		}
	}
	if result.Blocking > 0 {
		result.EffectBasisPts = blockingMitigationBPS
	} else {
		result.EffectBasisPts = smaller(result.Potential*potentialMitigationBPS, maxPotentialMitigationBPS)
	}
	sort.Strings(result.Reasons)
	return result
}

func pathNamespaces(path attackpath.Path, input snapshot.Snapshot) []string {
	set := make(map[string]struct{})
	if path.Target.Namespace == "" && clusterImpact(path.Target.Type) {
		for _, namespace := range observedNamespaces(input) {
			set[namespace] = struct{}{}
		}
	}
	if path.Source.Namespace != "" {
		set[path.Source.Namespace] = struct{}{}
	}
	if path.Target.Namespace != "" {
		set[path.Target.Namespace] = struct{}{}
	}
	for _, step := range path.Steps {
		for _, evidence := range step.Evidence {
			if evidence.Permission != nil && evidence.Permission.Namespace != "" && evidence.Permission.Namespace != "*" {
				set[evidence.Permission.Namespace] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(set))
	for namespace := range set {
		result = append(result, namespace)
	}
	sort.Strings(result)
	return result
}

func observedNamespaces(input snapshot.Snapshot) []string {
	set := make(map[string]struct{})
	add := func(namespace string) {
		if namespace != "" {
			set[namespace] = struct{}{}
		}
	}
	for _, identity := range input.Identities {
		add(identity.Namespace)
	}
	for _, role := range input.Roles {
		add(role.Ref.Namespace)
	}
	for _, binding := range input.Bindings {
		add(binding.Ref.Namespace)
	}
	for _, account := range input.ServiceAccounts {
		add(account.Ref.Namespace)
	}
	for _, workload := range input.Workloads {
		add(workload.Ref.Namespace)
	}
	for _, asset := range input.Assets {
		add(asset.Ref.Namespace)
	}
	for _, control := range input.SecurityControls {
		add(control.Ref.Namespace)
		if control.Ref.Kind == "Namespace" {
			add(control.Ref.Name)
		}
	}
	result := make([]string, 0, len(set))
	for namespace := range set {
		result = append(result, namespace)
	}
	sort.Strings(result)
	return result
}

func riskUnit(path attackpath.Path) string {
	return path.Source.String() + "\x00" + path.TemplateID + "\x00" + path.Target.Key
}

func severity(score int) Severity {
	switch {
	case score >= 85:
		return SeverityCritical
	case score >= 70:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	case score >= 1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func stableID(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + "-" + hex.EncodeToString(digest[:12])
}

func roundDivide(numerator, denominator int64) int {
	if denominator <= 0 {
		return 0
	}
	return int((numerator + denominator/2) / denominator)
}

func clamp(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func smaller(left, right int) int {
	if left < right {
		return left
	}
	return right
}
