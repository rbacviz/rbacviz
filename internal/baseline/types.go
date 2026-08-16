// Package baseline loads, validates, and evaluates reviewed risk exceptions.
// A baseline changes presentation and posture aggregation only; it never
// removes findings, attack paths, or evidence from analysis results.
package baseline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// SchemaVersion identifies the supported baseline document contract.
const SchemaVersion = "1.0"

// Profile records the operational context chosen by the baseline reviewer.
type Profile string

const (
	// ProfileProduction identifies a production review context.
	ProfileProduction Profile = "production"
	// ProfileDevelopment identifies a development review context.
	ProfileDevelopment Profile = "development"
	// ProfileDemo identifies a demonstration review context.
	ProfileDemo Profile = "demo"
)

// ObjectSelector matches one exact RoleBinding or ClusterRoleBinding.
type ObjectSelector struct {
	Kind      string `json:"kind" yaml:"kind"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name      string `json:"name" yaml:"name"`
}

// Suppression is one reviewed, expiring, exact exception selector.
type Suppression struct {
	ID           string          `json:"id" yaml:"id"`
	Rule         string          `json:"rule,omitempty" yaml:"rule,omitempty"`
	Subject      string          `json:"subject,omitempty" yaml:"subject,omitempty"`
	Binding      *ObjectSelector `json:"binding,omitempty" yaml:"binding,omitempty"`
	Namespace    string          `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	RiskFamilyID string          `json:"riskFamilyId,omitempty" yaml:"riskFamilyId,omitempty"`
	RootCauseKey string          `json:"rootCauseKey,omitempty" yaml:"rootCauseKey,omitempty"`
	Reason       string          `json:"reason" yaml:"reason"`
	Owner        string          `json:"owner" yaml:"owner"`
	Ticket       string          `json:"ticket,omitempty" yaml:"ticket,omitempty"`
	Expires      string          `json:"expires" yaml:"expires"`
}

// Document is the strict versioned baseline loaded by report and TUI commands.
type Document struct {
	SchemaVersion string        `json:"schemaVersion" yaml:"schemaVersion"`
	Profile       Profile       `json:"profile" yaml:"profile"`
	Suppressions  []Suppression `json:"suppressions" yaml:"suppressions"`
}

// State describes whether an exception was applied or needs review.
type State string

const (
	// StateAccepted means a non-expired entry matched exact analysis signals.
	StateAccepted State = "ACCEPTED"
	// StateExpired means an entry was not applied because its review expired.
	StateExpired State = "EXPIRED"
	// StateUnmatched means a current entry matched no analysis signal.
	StateUnmatched State = "UNMATCHED"
)

// Match records the exact analysis signals selected by one reviewed exception.
type Match struct {
	Suppression   Suppression `json:"suppression"`
	State         State       `json:"state"`
	FindingIDs    []string    `json:"findingIds"`
	RiskFamilyIDs []string    `json:"riskFamilyIds"`
	RootCauseKeys []string    `json:"rootCauseKeys"`
}

// Evaluation retains accepted, expired, and stale/unmatched entries separately.
type Evaluation struct {
	Profile   Profile `json:"profile"`
	Accepted  []Match `json:"accepted"`
	Expired   []Match `json:"expired"`
	Unmatched []Match `json:"unmatched"`
}

// AcceptedFindingIDs returns the exact findings selected by active exceptions.
func (value Evaluation) AcceptedFindingIDs() map[string]struct{} {
	return matchSet(value.Accepted, func(match Match) []string { return match.FindingIDs })
}

// AcceptedRiskFamilyIDs returns families excluded from active posture rollups.
func (value Evaluation) AcceptedRiskFamilyIDs() map[string]struct{} {
	return matchSet(value.Accepted, func(match Match) []string { return match.RiskFamilyIDs })
}

// AcceptedRootCauseKeys returns exact root causes selected by active exceptions.
func (value Evaluation) AcceptedRootCauseKeys() map[string]struct{} {
	result := make(map[string]struct{})
	for _, match := range value.Accepted {
		if match.Suppression.RootCauseKey != "" && len(match.RiskFamilyIDs) > 0 {
			result[match.Suppression.RootCauseKey] = struct{}{}
		}
	}
	return result
}

func matchSet(values []Match, selectValues func(Match) []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, value := range values {
		for _, selected := range selectValues(value) {
			result[selected] = struct{}{}
		}
	}
	return result
}

// ExpiredAt reports whether the inclusive expiry day has ended.
func (value Suppression) ExpiredAt(now time.Time) bool {
	expires, err := time.Parse(time.DateOnly, value.Expires)
	if err != nil {
		return true
	}
	deadline := expires.AddDate(0, 0, 1)
	return !now.UTC().Before(deadline)
}

// Validate rejects incomplete, ambiguous, broad, or incompatible baselines.
func Validate(value Document) error {
	if value.SchemaVersion != SchemaVersion {
		return fmt.Errorf("baseline schemaVersion must be %q", SchemaVersion)
	}
	if value.Profile != ProfileProduction && value.Profile != ProfileDevelopment && value.Profile != ProfileDemo {
		return fmt.Errorf("baseline profile must be production, development, or demo")
	}
	seen := make(map[string]struct{}, len(value.Suppressions))
	for index := range value.Suppressions {
		item := &value.Suppressions[index]
		normalizeSuppression(item)
		if item.ID == "" || item.Reason == "" || item.Owner == "" || item.Expires == "" {
			return fmt.Errorf("suppression %d requires id, reason, owner, and expires", index+1)
		}
		if _, found := seen[item.ID]; found {
			return fmt.Errorf("duplicate suppression id %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if _, err := time.Parse(time.DateOnly, item.Expires); err != nil {
			return fmt.Errorf("suppression %q has invalid expires date %q; use YYYY-MM-DD", item.ID, item.Expires)
		}
		if item.Rule == "" && item.RiskFamilyID == "" && item.RootCauseKey == "" {
			return fmt.Errorf("suppression %q requires an exact rule, riskFamilyId, or rootCauseKey", item.ID)
		}
		for _, candidate := range []string{item.Rule, item.Subject, item.Namespace, item.RiskFamilyID, item.RootCauseKey} {
			if strings.ContainsAny(candidate, "*?[") {
				return fmt.Errorf("suppression %q contains a wildcard; selectors must be exact", item.ID)
			}
		}
		if item.Subject != "" {
			if _, err := permission.ParseIdentity(item.Subject); err != nil {
				return fmt.Errorf("suppression %q has invalid subject: %w", item.ID, err)
			}
		}
		if item.Binding != nil {
			item.Binding.Kind = strings.TrimSpace(item.Binding.Kind)
			item.Binding.Namespace = strings.TrimSpace(item.Binding.Namespace)
			item.Binding.Name = strings.TrimSpace(item.Binding.Name)
			if item.Binding.Name == "" || (item.Binding.Kind != "RoleBinding" && item.Binding.Kind != "ClusterRoleBinding") {
				return fmt.Errorf("suppression %q binding requires kind RoleBinding or ClusterRoleBinding and an exact name", item.ID)
			}
			if item.Binding.Kind == "ClusterRoleBinding" && item.Binding.Namespace != "" {
				return fmt.Errorf("suppression %q ClusterRoleBinding cannot have a namespace", item.ID)
			}
		}
	}
	return nil
}

func normalizeSuppression(value *Suppression) {
	value.ID = strings.TrimSpace(value.ID)
	value.Rule = strings.TrimSpace(value.Rule)
	value.Subject = canonicalSubject(value.Subject)
	value.Namespace = strings.TrimSpace(value.Namespace)
	value.RiskFamilyID = strings.TrimSpace(value.RiskFamilyID)
	value.RootCauseKey = strings.TrimSpace(value.RootCauseKey)
	value.Reason = strings.TrimSpace(value.Reason)
	value.Owner = strings.TrimSpace(value.Owner)
	value.Ticket = strings.TrimSpace(value.Ticket)
	value.Expires = strings.TrimSpace(value.Expires)
}

func canonicalSubject(value string) string {
	value = strings.TrimSpace(value)
	prefix, remainder, found := strings.Cut(value, ":")
	if !found {
		return value
	}
	return strings.ToLower(prefix) + ":" + remainder
}

// Evaluate applies exact selectors to immutable findings and risk families.
// Expired entries are evaluated for visibility but never suppress a signal.
func Evaluate(document Document, findings analysis.Result, risks risk.Result, now time.Time) Evaluation {
	result := Evaluation{Profile: document.Profile, Accepted: []Match{}, Expired: []Match{}, Unmatched: []Match{}}
	for _, suppression := range document.Suppressions {
		match := evaluateOne(suppression, findings.Findings, risks.RiskFamilies)
		matched := len(match.FindingIDs) > 0 || len(match.RiskFamilyIDs) > 0
		switch {
		case suppression.ExpiredAt(now):
			match.State = StateExpired
			result.Expired = append(result.Expired, match)
		case !matched:
			match.State = StateUnmatched
			result.Unmatched = append(result.Unmatched, match)
		default:
			match.State = StateAccepted
			result.Accepted = append(result.Accepted, match)
		}
	}
	return result
}

func evaluateOne(suppression Suppression, findings []analysis.Finding, families []risk.Family) Match {
	match := Match{Suppression: suppression, FindingIDs: []string{}, RiskFamilyIDs: []string{}, RootCauseKeys: []string{}}
	rootKeys := make(map[string]struct{})
	for _, finding := range findings {
		if !matchesFinding(suppression, finding) {
			continue
		}
		match.FindingIDs = append(match.FindingIDs, finding.ID)
		for _, key := range findingRootCauseKeys(finding) {
			rootKeys[key] = struct{}{}
		}
	}
	for _, family := range families {
		if matchesFamily(suppression, family, rootKeys) {
			match.RiskFamilyIDs = append(match.RiskFamilyIDs, family.ID)
			rootKeys[family.RootCauseKey] = struct{}{}
		}
	}
	for key := range rootKeys {
		match.RootCauseKeys = append(match.RootCauseKeys, key)
	}
	sort.Strings(match.FindingIDs)
	sort.Strings(match.RiskFamilyIDs)
	sort.Strings(match.RootCauseKeys)
	return match
}

func matchesFinding(suppression Suppression, finding analysis.Finding) bool {
	if suppression.Rule != "" && suppression.Rule != finding.RuleID {
		return false
	}
	if suppression.Subject != "" && !findingHasSubject(finding, suppression.Subject) {
		return false
	}
	if suppression.Namespace != "" && !findingHasNamespace(finding, suppression.Namespace) {
		return false
	}
	if suppression.Binding != nil && !findingHasBinding(finding, *suppression.Binding) {
		return false
	}
	if suppression.RootCauseKey != "" && !contains(findingRootCauseKeys(finding), suppression.RootCauseKey) {
		return false
	}
	if suppression.RiskFamilyID != "" && suppression.Rule == "" && suppression.RootCauseKey == "" {
		return false
	}
	return true
}

func matchesFamily(suppression Suppression, family risk.Family, findingRoots map[string]struct{}) bool {
	if suppression.RiskFamilyID == "" && suppression.RootCauseKey == "" {
		return false
	}
	if suppression.RiskFamilyID != "" && suppression.RiskFamilyID != family.ID {
		return false
	}
	if suppression.RootCauseKey != "" && suppression.RootCauseKey != family.RootCauseKey {
		return false
	}
	if suppression.Rule != "" {
		if _, ok := findingRoots[family.RootCauseKey]; !ok {
			return false
		}
	}
	if suppression.Subject != "" && suppression.Subject != family.Source.String() {
		return false
	}
	if suppression.Namespace != "" && !familyHasNamespace(family, suppression.Namespace) {
		return false
	}
	if suppression.Binding != nil && !refMatches(family.BindingRef, *suppression.Binding) {
		return false
	}
	return suppression.Rule != "" || suppression.RiskFamilyID != "" || suppression.RootCauseKey != ""
}

func contains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func findingHasSubject(value analysis.Finding, subject string) bool {
	for _, identity := range value.AffectedIdentities {
		if identity.String() == subject {
			return true
		}
	}
	for _, evidence := range value.Evidence {
		if evidence.Grant == nil {
			continue
		}
		identity := permission.Identity{Kind: evidence.Grant.Subject.Kind, Namespace: evidence.Grant.Subject.Namespace, Name: evidence.Grant.Subject.Name}
		if identity.String() == subject {
			return true
		}
	}
	return false
}

func findingHasNamespace(value analysis.Finding, namespace string) bool {
	for _, identity := range value.AffectedIdentities {
		if identity.Namespace == namespace {
			return true
		}
	}
	for _, object := range value.AffectedObjects {
		if object.Namespace == namespace {
			return true
		}
	}
	for _, evidence := range value.Evidence {
		if evidence.Permission != nil && evidence.Permission.Namespace == namespace {
			return true
		}
	}
	return false
}

func findingHasBinding(value analysis.Finding, selector ObjectSelector) bool {
	for _, evidence := range value.Evidence {
		if evidence.Grant != nil && refMatches(&evidence.Grant.BindingRef, selector) {
			return true
		}
	}
	for index := range value.AffectedObjects {
		if refMatches(&value.AffectedObjects[index], selector) {
			return true
		}
	}
	return false
}

func familyHasNamespace(value risk.Family, namespace string) bool {
	if value.Source.Namespace == namespace {
		return true
	}
	return value.BindingRef != nil && value.BindingRef.Namespace == namespace
}

func refMatches(ref *snapshot.ObjectRef, selector ObjectSelector) bool {
	return ref != nil && ref.Kind == selector.Kind && ref.Name == selector.Name && ref.Namespace == selector.Namespace
}

func findingRootCauseKeys(value analysis.Finding) []string {
	set := make(map[string]struct{})
	for _, evidence := range value.Evidence {
		if evidence.Grant == nil {
			continue
		}
		identity := permission.Identity{Kind: evidence.Grant.Subject.Kind, Namespace: evidence.Grant.Subject.Namespace, Name: evidence.Grant.Subject.Name}
		set["grant|"+refKey(evidence.Grant.BindingRef)+"|"+identity.String()] = struct{}{}
	}
	if len(set) == 0 && len(value.AffectedIdentities) > 0 {
		for _, object := range value.AffectedObjects {
			if object.Kind != "RoleBinding" && object.Kind != "ClusterRoleBinding" {
				continue
			}
			for _, identity := range value.AffectedIdentities {
				set["grant|"+refKey(object)+"|"+identity.String()] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func refKey(value snapshot.ObjectRef) string {
	return strings.Join([]string{value.APIGroup, value.Kind, value.Namespace, value.Name}, "|")
}
