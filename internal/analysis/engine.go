package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// Rule is an independently testable, deterministic security observation.
type Rule interface {
	Metadata() RuleMetadata
	Evaluate(context.Context, EvaluationContext) ([]Finding, error)
}

// SubjectPermissions contains one observed identity and its effective grants.
type SubjectPermissions struct {
	Identity     permission.Identity
	Capabilities []permission.Capability
}

// EvaluationContext is immutable input shared by every enabled rule.
type EvaluationContext struct {
	Snapshot snapshot.Snapshot
	Subjects []SubjectPermissions
}

// Engine validates a rule set and evaluates it over one canonical snapshot.
type Engine struct {
	input snapshot.Snapshot
	rules []Rule
}

// New constructs a findings engine. An empty rule list enables all built-ins.
func New(input snapshot.Snapshot, rules ...Rule) (*Engine, error) {
	canonical, err := snapshot.Canonicalize(input)
	if err != nil {
		return nil, fmt.Errorf("canonicalize findings input: %w", err)
	}
	if len(rules) == 0 {
		rules = BuiltinRules()
	}
	rules = append([]Rule(nil), rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Metadata().ID < rules[j].Metadata().ID })
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		metadata := rule.Metadata()
		if err := validateMetadata(metadata); err != nil {
			return nil, err
		}
		if _, exists := seen[metadata.ID]; exists {
			return nil, fmt.Errorf("duplicate finding rule id %q", metadata.ID)
		}
		seen[metadata.ID] = struct{}{}
	}
	return &Engine{input: canonical, rules: rules}, nil
}

// Analyze resolves permissions once and evaluates every rule in stable order.
func (engine *Engine) Analyze(ctx context.Context) (Result, error) {
	resolver, err := permission.New(engine.input)
	if err != nil {
		return Result{}, fmt.Errorf("initialize findings permissions: %w", err)
	}
	evaluation := EvaluationContext{Snapshot: engine.input, Subjects: []SubjectPermissions{}}
	warnings := make([]Warning, 0, len(engine.input.Warnings))
	for _, warning := range engine.input.Warnings {
		warnings = append(warnings, Warning{Code: "Collection." + warning.Code, Message: warning.Resource + ": " + warning.Message})
	}
	for _, identity := range engine.input.Identities {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		query := permission.Identity{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name}
		result := resolver.Permissions(query, nil)
		evaluation.Subjects = append(evaluation.Subjects, SubjectPermissions{Identity: query, Capabilities: result.Capabilities})
		for _, warning := range result.Warnings {
			ref := warning.Ref
			warnings = append(warnings, Warning{Code: warning.Code, Message: warning.Message, Ref: optionalRef(ref)})
		}
	}

	findings := make([]Finding, 0)
	metadata := make([]RuleMetadata, 0, len(engine.rules))
	for _, rule := range engine.rules {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		metadata = append(metadata, canonicalMetadata(rule.Metadata()))
		values, err := rule.Evaluate(ctx, evaluation)
		if err != nil {
			return Result{}, fmt.Errorf("evaluate rule %s: %w", rule.Metadata().ID, err)
		}
		for _, value := range values {
			canonical, err := canonicalFinding(rule.Metadata(), value)
			if err != nil {
				return Result{}, fmt.Errorf("canonicalize rule %s finding: %w", rule.Metadata().ID, err)
			}
			findings = append(findings, canonical)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findingOrder(findings[i]) < findingOrder(findings[j]) })
	warnings = canonicalWarnings(warnings)
	return Result{
		SchemaVersion: ResultSchemaVersion, RulesetVersion: RulesetVersion,
		Complete: engine.input.Metadata.Complete && len(warnings) == 0,
		Rules:    metadata, Findings: findings, Warnings: warnings,
	}, nil
}

func canonicalFinding(metadata RuleMetadata, value Finding) (Finding, error) {
	if strings.TrimSpace(value.fingerprint) == "" {
		return Finding{}, fmt.Errorf("missing stable fingerprint")
	}
	value.ID = stableFindingID(metadata.ID, value.fingerprint)
	value.RuleID = metadata.ID
	value.Title = metadata.Title
	value.Severity = metadata.Severity
	value.RiskScore = metadata.RiskScore
	value.Description = strings.TrimSpace(value.Description)
	if value.Description == "" {
		value.Description = metadata.Description
	}
	value.SecurityImpact = metadata.SecurityImpact
	value.Recommendations = append([]string(nil), metadata.Recommendations...)
	value.References = append([]string(nil), metadata.References...)
	if value.Confidence == "" {
		value.Confidence = ConfidenceConfirmed
	}
	value.AffectedObjects = canonicalRefs(value.AffectedObjects)
	value.AffectedIdentities = canonicalIdentities(value.AffectedIdentities)
	value.Evidence = canonicalEvidence(value.Evidence)
	value.Preconditions = canonicalStrings(value.Preconditions)
	value.MitigatingControls = canonicalStrings(value.MitigatingControls)
	value.AttackPaths = canonicalStrings(value.AttackPaths)
	value.Recommendations = canonicalStrings(value.Recommendations)
	value.References = canonicalStrings(value.References)
	return value, nil
}

func stableFindingID(ruleID, fingerprint string) string {
	digest := sha256.Sum256([]byte(ruleID + "\x00" + fingerprint))
	return "RBACVIZ-" + strings.ToUpper(hex.EncodeToString(digest[:8]))
}

func validateMetadata(value RuleMetadata) error {
	if value.ID == "" || value.Title == "" || value.Description == "" || value.SecurityImpact == "" {
		return fmt.Errorf("finding rule %q has incomplete metadata", value.ID)
	}
	if value.RiskScore < 0 || value.RiskScore > 100 {
		return fmt.Errorf("finding rule %q risk score must be between 0 and 100", value.ID)
	}
	switch value.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return nil
	default:
		return fmt.Errorf("finding rule %q has invalid severity %q", value.ID, value.Severity)
	}
}

func canonicalMetadata(value RuleMetadata) RuleMetadata {
	value.Recommendations = canonicalStrings(value.Recommendations)
	value.References = canonicalStrings(value.References)
	return value
}

func canonicalRefs(values []snapshot.ObjectRef) []snapshot.ObjectRef {
	sort.Slice(values, func(i, j int) bool { return objectKey(values[i]) < objectKey(values[j]) })
	return deduplicate(values, objectKey)
}

func canonicalIdentities(values []permission.Identity) []permission.Identity {
	sort.Slice(values, func(i, j int) bool { return identityKey(values[i]) < identityKey(values[j]) })
	return deduplicate(values, identityKey)
}

func canonicalEvidence(values []Evidence) []Evidence {
	sort.Slice(values, func(i, j int) bool { return evidenceKey(values[i]) < evidenceKey(values[j]) })
	return deduplicate(values, evidenceKey)
}

func canonicalStrings(values []string) []string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return deduplicate(values, func(value string) string { return value })
}

func canonicalWarnings(values []Warning) []Warning {
	sort.Slice(values, func(i, j int) bool { return warningKey(values[i]) < warningKey(values[j]) })
	return deduplicate(values, warningKey)
}

func deduplicate[T any](values []T, key func(T) string) []T {
	if len(values) == 0 {
		return []T{}
	}
	result := make([]T, 0, len(values))
	last := ""
	for index, value := range values {
		current := key(value)
		if index == 0 || current != last {
			result = append(result, value)
			last = current
		}
	}
	return result
}

func evidenceKey(value Evidence) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func warningKey(value Warning) string {
	ref := ""
	if value.Ref != nil {
		ref = objectKey(*value.Ref)
	}
	return value.Code + "\x00" + value.Message + "\x00" + ref
}

func findingOrder(value Finding) string {
	return fmt.Sprintf("%03d\x00%s\x00%s", 100-value.RiskScore, value.RuleID, value.ID)
}

func identityKey(value permission.Identity) string {
	return string(value.Kind) + "\x00" + value.Namespace + "\x00" + value.Name
}

func objectKey(value snapshot.ObjectRef) string {
	return value.APIGroup + "\x00" + value.Kind + "\x00" + value.Namespace + "\x00" + value.Name
}

func optionalRef(value snapshot.ObjectRef) *snapshot.ObjectRef {
	if value.Kind == "" && value.Name == "" {
		return nil
	}
	refCopy := value
	return &refCopy
}
