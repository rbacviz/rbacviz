package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/rbacviz/rbacviz/internal/permission"
)

func (engine *Engine) materialize(value candidate) Path {
	confidence, reasons := engine.composeConfidence(value)
	cost := calculateCost(value.metadata, value.prerequisites, value.controls, confidence)
	evidence := candidateEvidence(value)
	sourceNode := NodeRef{Type: "IDENTITY", Key: value.source.String(), Name: value.source.Name, Namespace: value.source.Namespace}
	techniqueNode := NodeRef{Type: "ATTACK_TECHNIQUE", Key: "attack-technique:" + value.metadata.ID, Name: value.metadata.Title}
	targetNode := NodeRef{Type: "PRIVILEGE_TARGET", Key: value.target.Key, Name: string(value.target.Type), Namespace: value.target.Namespace}
	first := AttackStep{
		From: sourceNode, To: techniqueNode, Relation: "ENABLES", TechniqueID: value.metadata.ID,
		Description: value.metadata.Description, Evidence: evidence,
		Prerequisites: canonicalPrerequisites(value.prerequisites), MitigatingControls: canonicalControls(value.controls),
		Confidence: confidence, ConfidenceReasons: reasons, Cost: cost,
		RemediationCandidates: canonicalStrings(value.metadata.Remediations),
	}
	first.ID = stableStepID(first)
	second := AttackStep{
		From: techniqueNode, To: targetNode, Relation: "REACHES", TechniqueID: value.metadata.ID,
		Description:   "Successful technique reaches " + string(value.target.Type) + ".",
		Evidence:      []StepEvidence{{Field: "template.target", Value: string(value.target.Type)}},
		Prerequisites: []Prerequisite{}, MitigatingControls: []MitigationObservation{},
		Confidence: confidence, ConfidenceReasons: append([]string(nil), reasons...),
		Cost: CostBreakdown{}, RemediationCandidates: canonicalStrings(value.metadata.Remediations),
	}
	second.ID = stableStepID(second)
	path := Path{TemplateID: value.metadata.ID, Title: value.metadata.Title, Source: value.source, Target: value.target, Steps: []AttackStep{first, second}, Confidence: confidence, ConfidenceReasons: reasons, Cost: cost.Total, Blocked: confidence == ConfidenceBlocked}
	path.ID = stablePathID(path)
	return path
}

func (engine *Engine) composeConfidence(value candidate) (Confidence, []string) {
	confidence := value.baseConfidence
	if confidence == "" {
		confidence = ConfidenceLikely
	}
	reasons := append([]string(nil), value.reasons...)
	for _, prerequisite := range value.prerequisites {
		switch prerequisite.State {
		case PrerequisiteUnknown:
			confidence = moreRestrictive(confidence, ConfidenceUnknown)
			reasons = append(reasons, prerequisite.Description+" is unknown")
		case PrerequisiteRequired:
			confidence = moreRestrictive(confidence, ConfidenceConditional)
			reasons = append(reasons, prerequisite.Description+" is required")
		}
	}
	for _, control := range value.controls {
		switch control.State {
		case MitigationBlocking:
			confidence = ConfidenceBlocked
			reasons = append(reasons, control.Reason)
		case MitigationPotential:
			confidence = moreRestrictive(confidence, ConfidenceUnknown)
			reasons = append(reasons, control.Reason)
		}
	}
	if !engine.input.Metadata.Complete && confidence != ConfidenceBlocked {
		confidence = moreRestrictive(confidence, ConfidenceUnknown)
		reasons = append(reasons, "collection is incomplete; inaccessible data is not treated as absent")
	}
	if value.capability != nil && value.capability.Scope == permission.ScopeUnknown && confidence != ConfidenceBlocked {
		confidence = moreRestrictive(confidence, ConfidenceUnknown)
		reasons = append(reasons, "API discovery could not establish resource scope")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "all modeled prerequisites are directly observed")
	}
	return confidence, canonicalStrings(reasons)
}

func moreRestrictive(left, right Confidence) Confidence {
	if confidenceRank(right) > confidenceRank(left) {
		return right
	}
	return left
}

func confidenceRank(value Confidence) int {
	switch value {
	case ConfidenceBlocked:
		return 5
	case ConfidenceUnknown:
		return 4
	case ConfidenceConditional:
		return 3
	case ConfidenceLikely:
		return 2
	default:
		return 1
	}
}

func calculateCost(metadata TemplateMetadata, prerequisites []Prerequisite, controls []MitigationObservation, confidence Confidence) CostBreakdown {
	value := CostBreakdown{BaseTechnique: metadata.BaseCost, OperationalComplexity: metadata.OperationalComplexity}
	for _, prerequisite := range prerequisites {
		switch prerequisite.State {
		case PrerequisiteRequired:
			value.PrerequisitePenalty += 3
		case PrerequisiteUnknown:
			value.PrerequisitePenalty += 5
		}
	}
	switch confidence {
	case ConfidenceUnknown:
		value.UncertaintyPenalty += 5
	case ConfidenceConditional:
		value.UncertaintyPenalty += 2
	}
	for _, control := range controls {
		switch control.State {
		case MitigationPotential:
			value.MitigationPenalty += 4
		case MitigationBlocking:
			value.MitigationPenalty += 1000
		}
	}
	value.Total = value.BaseTechnique + value.PrerequisitePenalty + value.UncertaintyPenalty + value.MitigationPenalty + value.OperationalComplexity
	return value
}

func candidateEvidence(value candidate) []StepEvidence {
	result := make([]StepEvidence, 0, 2)
	if value.capability != nil {
		capability := value.capability
		result = append(result, StepEvidence{Permission: &PermissionEvidence{Verb: capability.Verb, APIGroup: capability.APIGroup, Resource: capability.Resource, Subresource: capability.Subresource, ResourceNames: append([]string(nil), capability.ResourceNames...), Scope: capability.Scope, Namespace: capability.Namespace}})
	}
	if value.grant != nil {
		grant := *value.grant
		result = append(result, StepEvidence{Grant: &grant})
	}
	if value.object != nil {
		ref := *value.object
		result = append(result, StepEvidence{Ref: &ref, Field: value.objectField, Value: value.objectValue})
	}
	return result
}

func canonicalPaths(values []Path) []Path {
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if left.Blocked != right.Blocked {
			return !left.Blocked
		}
		if left.Cost != right.Cost {
			return left.Cost < right.Cost
		}
		if left.Target.PrivilegeGain != right.Target.PrivilegeGain {
			return left.Target.PrivilegeGain > right.Target.PrivilegeGain
		}
		if left.Target.BlastRadius != right.Target.BlastRadius {
			return left.Target.BlastRadius > right.Target.BlastRadius
		}
		if confidenceRank(left.Confidence) != confidenceRank(right.Confidence) {
			return confidenceRank(left.Confidence) < confidenceRank(right.Confidence)
		}
		return left.ID < right.ID
	})
	result := make([]Path, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1].ID != value.ID {
			result = append(result, value)
		}
	}
	return result
}

func stableStepID(value AttackStep) string { return stableJSONID("step", value) }
func stablePathID(value Path) string {
	value.ID = ""
	return stableJSONID("attack-path", value)
}
func stableJSONID(prefix string, value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return prefix + "-" + hex.EncodeToString(digest[:12])
}

func canonicalPrerequisites(values []Prerequisite) []Prerequisite {
	if len(values) == 0 {
		return []Prerequisite{}
	}
	result := append([]Prerequisite(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
func canonicalStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write == 0 || result[write-1] != value {
			result[write] = value
			write++
		}
	}
	return result[:write]
}
func sortControls(values []MitigationObservation) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}
