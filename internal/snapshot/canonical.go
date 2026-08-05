package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Canonicalize returns a deep-copied snapshot in the single persisted order.
func Canonicalize(input Snapshot) (Snapshot, error) {
	output, err := clone(input)
	if err != nil {
		return Snapshot{}, fmt.Errorf("clone snapshot: %w", err)
	}
	normalizeNilSlices(&output)

	for index := range output.APIResources {
		resource := &output.APIResources[index]
		resource.Verbs = sortedUnique(resource.Verbs)
	}
	sort.Slice(output.APIResources, func(i, j int) bool {
		return apiResourceKey(output.APIResources[i]) < apiResourceKey(output.APIResources[j])
	})

	for index := range output.Roles {
		role := &output.Roles[index]
		role.Labels = canonicalPairs(role.Labels)
		for selectorIndex := range role.AggregationSelectors {
			selector := &role.AggregationSelectors[selectorIndex]
			selector.MatchLabels = canonicalPairs(selector.MatchLabels)
			for expressionIndex := range selector.MatchExpressions {
				expression := &selector.MatchExpressions[expressionIndex]
				expression.Values = sortedUnique(expression.Values)
			}
			sort.Slice(selector.MatchExpressions, func(i, j int) bool {
				return selectorRequirementKey(selector.MatchExpressions[i]) < selectorRequirementKey(selector.MatchExpressions[j])
			})
		}
		sort.Slice(role.AggregationSelectors, func(i, j int) bool {
			return selectorKey(role.AggregationSelectors[i]) < selectorKey(role.AggregationSelectors[j])
		})
		for ruleIndex := range role.Rules {
			rule := &role.Rules[ruleIndex]
			rule.Verbs = sortedUnique(rule.Verbs)
			rule.APIGroups = sortedUnique(rule.APIGroups)
			rule.Resources = sortedUnique(rule.Resources)
			rule.ResourceNames = sortedUnique(rule.ResourceNames)
			rule.NonResourceURLs = sortedUnique(rule.NonResourceURLs)
			rule.ID = stableID("rule", objectKey(role.Ref)+"|"+ruleKey(*rule))
		}
		sort.Slice(role.Rules, func(i, j int) bool { return ruleKey(role.Rules[i]) < ruleKey(role.Rules[j]) })
		role.ID = stableID("role", objectKey(role.Ref))
	}
	sort.Slice(output.Roles, func(i, j int) bool { return objectKey(output.Roles[i].Ref) < objectKey(output.Roles[j].Ref) })

	for index := range output.Bindings {
		binding := &output.Bindings[index]
		binding.Labels = canonicalPairs(binding.Labels)
		for subjectIndex := range binding.Subjects {
			subject := &binding.Subjects[subjectIndex]
			if subject.Kind == IdentityServiceAccount && subject.Namespace == "" {
				subject.Namespace = binding.Ref.Namespace
			}
		}
		sort.Slice(binding.Subjects, func(i, j int) bool {
			return subjectKey(binding.Subjects[i]) < subjectKey(binding.Subjects[j])
		})
		binding.Subjects = dedupeSubjects(binding.Subjects)
		binding.ID = stableID("binding", objectKey(binding.Ref))
	}
	sort.Slice(output.Bindings, func(i, j int) bool { return objectKey(output.Bindings[i].Ref) < objectKey(output.Bindings[j].Ref) })

	for index := range output.ServiceAccounts {
		account := &output.ServiceAccounts[index]
		account.Labels = canonicalPairs(account.Labels)
		account.ID = stableID("service-account", objectKey(account.Ref))
	}
	sort.Slice(output.ServiceAccounts, func(i, j int) bool {
		return objectKey(output.ServiceAccounts[i].Ref) < objectKey(output.ServiceAccounts[j].Ref)
	})

	output.Identities = canonicalIdentities(output.Identities, output.Bindings, output.ServiceAccounts)

	for index := range output.Workloads {
		workload := &output.Workloads[index]
		workload.Labels = canonicalPairs(workload.Labels)
		sort.Slice(workload.Owners, func(i, j int) bool { return objectKey(workload.Owners[i].Ref) < objectKey(workload.Owners[j].Ref) })
		workload.Images = sortedUnique(workload.Images)
		workload.PrivilegedContainers = sortedUnique(workload.PrivilegedContainers)
		sort.Slice(workload.Volumes, func(i, j int) bool { return volumeKey(workload.Volumes[i]) < volumeKey(workload.Volumes[j]) })
		workload.ID = stableID("workload", objectKey(workload.Ref))
	}
	sort.Slice(output.Workloads, func(i, j int) bool { return objectKey(output.Workloads[i].Ref) < objectKey(output.Workloads[j].Ref) })

	for index := range output.Assets {
		asset := &output.Assets[index]
		asset.Labels = canonicalPairs(asset.Labels)
		asset.ID = stableID("asset", objectKey(asset.Ref))
	}
	sort.Slice(output.Assets, func(i, j int) bool { return objectKey(output.Assets[i].Ref) < objectKey(output.Assets[j].Ref) })

	for index := range output.SecurityControls {
		control := &output.SecurityControls[index]
		control.Details = canonicalPairs(control.Details)
		control.ID = stableID("security-control", objectKey(control.Ref)+"|"+control.ControlType)
	}
	sort.Slice(output.SecurityControls, func(i, j int) bool {
		return controlKey(output.SecurityControls[i]) < controlKey(output.SecurityControls[j])
	})

	sort.Slice(output.Warnings, func(i, j int) bool { return warningKey(output.Warnings[i]) < warningKey(output.Warnings[j]) })
	output.Metadata.Complete = len(output.Warnings) == 0
	if err := Validate(output); err != nil {
		return Snapshot{}, err
	}
	return output, nil
}

// SemanticDigest excludes non-semantic collection time, context, cluster
// fingerprint, and tool build while retaining completeness evidence.
func SemanticDigest(input Snapshot) (string, error) {
	canonical, err := Canonicalize(input)
	if err != nil {
		return "", err
	}
	canonical.ToolVersion = ""
	canonical.Metadata.CollectedAt = ""
	canonical.Metadata.Context = ""
	canonical.Metadata.ClusterFingerprint = ""
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal semantic snapshot: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// Validate checks the schema major version and portable object invariants.
func Validate(value Snapshot) error {
	if schemaMajor(value.SchemaVersion) != schemaMajor(SchemaVersion) {
		return fmt.Errorf("unsupported snapshot schema version %q", value.SchemaVersion)
	}
	if value.Metadata.CollectedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, value.Metadata.CollectedAt); err != nil {
			return fmt.Errorf("invalid collection timestamp %q", value.Metadata.CollectedAt)
		}
	}
	seen := make(map[string]string)
	register := func(id, key string) error {
		if id == "" {
			return fmt.Errorf("missing stable id for %s", key)
		}
		if previous, ok := seen[id]; ok && previous != key {
			return fmt.Errorf("stable id collision between %s and %s", previous, key)
		}
		seen[id] = key
		return nil
	}
	for _, role := range value.Roles {
		if err := validateRef(role.Ref); err != nil {
			return err
		}
		if err := register(role.ID, "role:"+objectKey(role.Ref)); err != nil {
			return err
		}
		for _, rule := range role.Rules {
			if err := register(rule.ID, "rule:"+objectKey(role.Ref)+":"+ruleKey(rule)); err != nil {
				return err
			}
		}
	}
	for _, binding := range value.Bindings {
		if err := validateRef(binding.Ref); err != nil {
			return err
		}
		if err := validateRef(binding.RoleRef); err != nil {
			return err
		}
		if err := register(binding.ID, "binding:"+objectKey(binding.Ref)); err != nil {
			return err
		}
	}
	for _, identity := range value.Identities {
		if identity.Name == "" {
			return fmt.Errorf("identity name cannot be empty")
		}
		if identity.Kind == IdentityServiceAccount && identity.Namespace == "" {
			return fmt.Errorf("service account identity %q has no namespace", identity.Name)
		}
		if err := register(identity.ID, "identity:"+identityKey(identity)); err != nil {
			return err
		}
	}
	for _, account := range value.ServiceAccounts {
		if err := validateRef(account.Ref); err != nil {
			return err
		}
		if err := register(account.ID, "service-account:"+objectKey(account.Ref)); err != nil {
			return err
		}
	}
	for _, workload := range value.Workloads {
		if err := validateRef(workload.Ref); err != nil {
			return err
		}
		if err := register(workload.ID, "workload:"+objectKey(workload.Ref)); err != nil {
			return err
		}
	}
	for _, asset := range value.Assets {
		if err := validateRef(asset.Ref); err != nil {
			return err
		}
		if err := register(asset.ID, "asset:"+objectKey(asset.Ref)); err != nil {
			return err
		}
	}
	for _, control := range value.SecurityControls {
		if err := validateRef(control.Ref); err != nil {
			return err
		}
		if err := register(control.ID, "control:"+controlKey(control)); err != nil {
			return err
		}
	}
	return nil
}

func canonicalIdentities(existing []Identity, bindings []Binding, accounts []ServiceAccount) []Identity {
	byKey := make(map[string]Identity)
	merge := func(identity Identity, provenance ObjectRef) {
		key := identityKey(identity)
		current := byKey[key]
		if current.Name == "" {
			current = identity
		}
		if provenance.Name != "" {
			current.Provenance = append(current.Provenance, provenance)
		}
		byKey[key] = current
	}
	for _, identity := range existing {
		for _, provenance := range identity.Provenance {
			merge(identity, provenance)
		}
		if len(identity.Provenance) == 0 {
			merge(identity, ObjectRef{})
		}
	}
	for _, account := range accounts {
		merge(Identity{Kind: IdentityServiceAccount, Namespace: account.Ref.Namespace, Name: account.Ref.Name}, account.Ref)
	}
	for _, binding := range bindings {
		for _, subject := range binding.Subjects {
			merge(Identity{Kind: subject.Kind, Namespace: subject.Namespace, Name: subject.Name}, binding.Ref)
		}
	}
	result := make([]Identity, 0, len(byKey))
	for _, identity := range byKey {
		sort.Slice(identity.Provenance, func(i, j int) bool { return objectKey(identity.Provenance[i]) < objectKey(identity.Provenance[j]) })
		identity.Provenance = dedupeRefs(identity.Provenance)
		identity.ID = stableID("identity", identityKey(identity))
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool { return identityKey(result[i]) < identityKey(result[j]) })
	return result
}

func stableID(prefix, key string) string {
	digest := sha256.Sum256([]byte(prefix + "\x00" + key))
	return prefix + "-" + hex.EncodeToString(digest[:12])
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) == 0 {
		return []string{}
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] != result[write-1] {
			result[write] = result[read]
			write++
		}
	}
	return result[:write]
}

func canonicalPairs(values []KeyValue) []KeyValue {
	result := append([]KeyValue(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Key == result[j].Key {
			return result[i].Value < result[j].Value
		}
		return result[i].Key < result[j].Key
	})
	if len(result) == 0 {
		return []KeyValue{}
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] != result[write-1] {
			result[write] = result[read]
			write++
		}
	}
	return result[:write]
}

func clone(input Snapshot) (Snapshot, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return Snapshot{}, err
	}
	var output Snapshot
	if err := json.Unmarshal(data, &output); err != nil {
		return Snapshot{}, err
	}
	return output, nil
}

func normalizeNilSlices(value *Snapshot) {
	if value.APIResources == nil {
		value.APIResources = []APIResource{}
	}
	if value.Identities == nil {
		value.Identities = []Identity{}
	}
	if value.Roles == nil {
		value.Roles = []Role{}
	}
	if value.Bindings == nil {
		value.Bindings = []Binding{}
	}
	if value.ServiceAccounts == nil {
		value.ServiceAccounts = []ServiceAccount{}
	}
	if value.Workloads == nil {
		value.Workloads = []Workload{}
	}
	if value.Assets == nil {
		value.Assets = []Asset{}
	}
	if value.SecurityControls == nil {
		value.SecurityControls = []SecurityControl{}
	}
	if value.Warnings == nil {
		value.Warnings = []Warning{}
	}
	for i := range value.APIResources {
		if value.APIResources[i].Verbs == nil {
			value.APIResources[i].Verbs = []string{}
		}
	}
	for i := range value.Roles {
		if value.Roles[i].Labels == nil {
			value.Roles[i].Labels = []KeyValue{}
		}
		if value.Roles[i].Rules == nil {
			value.Roles[i].Rules = []PolicyRule{}
		}
		if value.Roles[i].AggregationSelectors == nil {
			value.Roles[i].AggregationSelectors = []LabelSelector{}
		}
		for j := range value.Roles[i].Rules {
			rule := &value.Roles[i].Rules[j]
			if rule.Verbs == nil {
				rule.Verbs = []string{}
			}
			if rule.APIGroups == nil {
				rule.APIGroups = []string{}
			}
			if rule.Resources == nil {
				rule.Resources = []string{}
			}
			if rule.ResourceNames == nil {
				rule.ResourceNames = []string{}
			}
			if rule.NonResourceURLs == nil {
				rule.NonResourceURLs = []string{}
			}
		}
	}
	for i := range value.Bindings {
		if value.Bindings[i].Labels == nil {
			value.Bindings[i].Labels = []KeyValue{}
		}
		if value.Bindings[i].Subjects == nil {
			value.Bindings[i].Subjects = []Subject{}
		}
	}
	for i := range value.ServiceAccounts {
		if value.ServiceAccounts[i].Labels == nil {
			value.ServiceAccounts[i].Labels = []KeyValue{}
		}
	}
	for i := range value.Workloads {
		workload := &value.Workloads[i]
		if workload.Labels == nil {
			workload.Labels = []KeyValue{}
		}
		if workload.Owners == nil {
			workload.Owners = []OwnerReference{}
		}
		if workload.PrivilegedContainers == nil {
			workload.PrivilegedContainers = []string{}
		}
		if workload.Images == nil {
			workload.Images = []string{}
		}
		if workload.Volumes == nil {
			workload.Volumes = []VolumeReference{}
		}
	}
	for i := range value.Assets {
		if value.Assets[i].Labels == nil {
			value.Assets[i].Labels = []KeyValue{}
		}
	}
	for i := range value.SecurityControls {
		if value.SecurityControls[i].Details == nil {
			value.SecurityControls[i].Details = []KeyValue{}
		}
	}
}

func objectKey(ref ObjectRef) string {
	return strings.Join([]string{ref.APIGroup, ref.Kind, ref.Namespace, ref.Name}, "|")
}
func apiResourceKey(value APIResource) string {
	return strings.Join([]string{value.GroupVersion, value.Name, value.Kind}, "|")
}
func identityKey(value Identity) string {
	return strings.Join([]string{string(value.Kind), value.Namespace, value.Name}, "|")
}
func subjectKey(value Subject) string {
	return strings.Join([]string{string(value.Kind), value.Namespace, value.Name, value.APIGroup}, "|")
}
func ruleKey(value PolicyRule) string {
	return strings.Join([]string{strings.Join(value.Verbs, ","), strings.Join(value.APIGroups, ","), strings.Join(value.Resources, ","), strings.Join(value.ResourceNames, ","), strings.Join(value.NonResourceURLs, ",")}, "|")
}
func volumeKey(value VolumeReference) string {
	return strings.Join([]string{value.Kind, value.Namespace, value.Target, value.Name}, "|")
}
func controlKey(value SecurityControl) string { return objectKey(value.Ref) + "|" + value.ControlType }
func warningKey(value Warning) string         { return value.Resource + "|" + value.Code + "|" + value.Message }
func selectorRequirementKey(value SelectorRequirement) string {
	return value.Key + "|" + value.Operator + "|" + strings.Join(value.Values, ",")
}
func selectorKey(value LabelSelector) string { data, _ := json.Marshal(value); return string(data) }
func schemaMajor(value string) string {
	if index := strings.IndexByte(value, '.'); index >= 0 {
		return value[:index]
	}
	return value
}

func validateRef(ref ObjectRef) error {
	if ref.Kind == "" || ref.Name == "" {
		return fmt.Errorf("invalid object reference %q/%q", ref.Kind, ref.Name)
	}
	return nil
}

func dedupeSubjects(values []Subject) []Subject {
	if len(values) == 0 {
		return []Subject{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if subjectKey(values[read]) != subjectKey(values[write-1]) {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}

func dedupeRefs(values []ObjectRef) []ObjectRef {
	if len(values) == 0 {
		return []ObjectRef{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if objectKey(values[read]) != objectKey(values[write-1]) {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}
