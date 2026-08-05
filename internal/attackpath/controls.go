package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func (engine *Engine) controlsFor(templateID, namespace string) []MitigationObservation {
	if !mutationTechnique(templateID) {
		return []MitigationObservation{}
	}
	result := make([]MitigationObservation, 0)
	for _, control := range engine.input.SecurityControls {
		if control.Ref.Namespace != "" && namespace != "" && control.Ref.Namespace != namespace {
			continue
		}
		observation, applies := evaluateControl(templateID, namespace, control)
		if applies {
			result = append(result, observation)
		}
	}
	return canonicalControls(result)
}

func mutationTechnique(templateID string) bool {
	switch templateID {
	case "RBACVIZ-AP004", "RBACVIZ-AP006", "RBACVIZ-AP007", "RBACVIZ-AP008", "RBACVIZ-AP011", "RBACVIZ-AP012":
		return true
	default:
		return false
	}
}

func evaluateControl(templateID, namespace string, value snapshot.SecurityControl) (MitigationObservation, bool) {
	state := MitigationObserved
	known := !value.SemanticsUnknown
	reason := "control metadata was observed; this template does not claim full policy evaluation"
	if value.SemanticsUnknown {
		state = MitigationPotential
		known = false
		reason = "control semantics were not evaluated and may constrain this mutation"
	}
	if value.ControlType == "PodSecurityAdmission" {
		if templateID != "RBACVIZ-AP012" && templateID != "RBACVIZ-AP004" {
			return MitigationObservation{}, false
		}
		if namespace != "" && value.Ref.Kind == "Namespace" && value.Ref.Name != namespace {
			return MitigationObservation{}, false
		}
		known = true
		mode := strings.ToLower(value.Mode)
		if templateID == "RBACVIZ-AP012" && (mode == "baseline" || mode == "restricted") {
			state = MitigationBlocking
			reason = "Pod Security Admission enforce=" + mode + " rejects the modeled privileged/host-access Pod specification"
		} else {
			state = MitigationObserved
			reason = "Pod Security Admission labels were observed for namespace " + namespace
		}
	}
	key := value.ControlType + "\x00" + value.Ref.APIGroup + "\x00" + value.Ref.Kind + "\x00" + value.Ref.Namespace + "\x00" + value.Ref.Name + "\x00" + templateID
	digest := sha256.Sum256([]byte(key))
	return MitigationObservation{ID: "mit-" + hex.EncodeToString(digest[:8]), ControlType: value.ControlType, Ref: value.Ref, State: state, SemanticsKnown: known, Reason: reason}, true
}

func canonicalControls(values []MitigationObservation) []MitigationObservation {
	if len(values) == 0 {
		return []MitigationObservation{}
	}
	result := append([]MitigationObservation(nil), values...)
	sortControls(result)
	return result
}
