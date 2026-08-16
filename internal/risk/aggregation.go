package risk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rbacviz/rbacviz/internal/attackpath"
	"github.com/rbacviz/rbacviz/internal/permission"
)

const maxFamilyDiversityContribution = 12

var additionalFamilyWeightsPercent = []int{5, 3, 2, 1, 1}

func aggregateAll(paths []PathScore) ([]AggregateScore, []AggregateScore, AggregateScore) {
	identityGroups := make(map[string][]PathScore)
	namespaceGroups := make(map[string][]PathScore)
	for _, path := range paths {
		identityGroups[path.Source.String()] = append(identityGroups[path.Source.String()], path)
		for _, namespace := range path.Namespaces {
			namespaceGroups[namespace] = append(namespaceGroups[namespace], path)
		}
	}

	identities := make([]AggregateScore, 0, len(identityGroups))
	for key, values := range identityGroups {
		identity := values[0].Source
		identities = append(identities, aggregate(AggregateIdentity, key, &identity, "", values))
	}
	namespaces := make([]AggregateScore, 0, len(namespaceGroups))
	for namespace, values := range namespaceGroups {
		namespaces = append(namespaces, aggregate(AggregateNamespace, namespace, nil, namespace, values))
	}
	sortAggregates(identities)
	sortAggregates(namespaces)
	cluster := aggregate(AggregateCluster, "cluster", nil, "", paths)
	return identities, namespaces, cluster
}

// WithoutFamilies returns a re-aggregated active posture result while leaving
// the input untouched. Callers must retain the original result alongside the
// reviewed exception records so accepted evidence never disappears.
func WithoutFamilies(value Result, excluded map[string]struct{}) Result {
	if len(excluded) == 0 {
		return value
	}
	paths := make([]PathScore, 0, len(value.PathScores))
	for _, path := range value.PathScores {
		if _, found := excluded[path.RiskFamilyID]; !found {
			paths = append(paths, path)
		}
	}
	value.PathScores = paths
	value.RiskFamilies = buildRiskFamilies(paths)
	value.Identities, value.Namespaces, value.Cluster = aggregateAll(paths)
	return value
}

func aggregate(kind AggregateKind, key string, identity *permission.Identity, namespace string, paths []PathScore) AggregateScore {
	pathIDs := make([]string, 0, len(paths))
	riskUnits := make(map[string]struct{})
	for _, path := range paths {
		pathIDs = append(pathIDs, path.PathID)
		riskUnits[path.RiskUnit] = struct{}{}
	}
	sort.Strings(pathIDs)
	pathIDs = uniqueStrings(pathIDs)

	families := buildRiskFamilies(paths)
	familyIDs := make([]string, 0, len(families))
	for _, family := range families {
		familyIDs = append(familyIDs, family.ID)
	}
	sort.Strings(familyIDs)

	// Different bindings that yield the exact same set of semantic outcomes do
	// not expand attack surface. Keep both root causes visible, but choose one
	// deterministic representative for aggregate scoring.
	representatives := make(map[string]Family)
	for _, family := range families {
		current, found := representatives[family.SemanticKey]
		if !found || family.Score > current.Score || (family.Score == current.Score && family.ID < current.ID) {
			representatives[family.SemanticKey] = family
		}
	}
	contributors := make([]Family, 0, len(representatives))
	for _, family := range representatives {
		contributors = append(contributors, family)
	}
	sort.Slice(contributors, func(i, j int) bool {
		if contributors[i].Score != contributors[j].Score {
			return contributors[i].Score > contributors[j].Score
		}
		return contributors[i].ID < contributors[j].ID
	})

	contributions := make([]FamilyContribution, 0, smaller(len(contributors), len(additionalFamilyWeightsPercent)+1))
	primary, additional := 0, 0
	if len(contributors) > 0 {
		primary = contributors[0].Score
		contributions = append(contributions, FamilyContribution{
			FamilyID: contributors[0].ID, SemanticKey: contributors[0].SemanticKey,
			Score: contributors[0].Score, Weight: 100, Contribution: primary, Primary: true,
		})
		for index, family := range contributors[1:] {
			if index >= len(additionalFamilyWeightsPercent) || additional >= maxFamilyDiversityContribution {
				break
			}
			weight := additionalFamilyWeightsPercent[index]
			value := roundDivide(int64(family.Score*weight), 100)
			if remaining := maxFamilyDiversityContribution - additional; value > remaining {
				value = remaining
			}
			if headroom := 100 - primary - additional; value > headroom {
				value = headroom
			}
			if value <= 0 {
				break
			}
			additional += value
			contributions = append(contributions, FamilyContribution{
				FamilyID: family.ID, SemanticKey: family.SemanticKey,
				Score: family.Score, Weight: weight, Contribution: value,
			})
		}
	}
	score := clamp(primary + additional)
	return AggregateScore{
		Kind: kind, Key: key, Identity: identity, Namespace: namespace,
		Score: score, Severity: severity(score), PrimaryScore: primary,
		AdditionalContribution: additional, DistinctRiskUnits: len(riskUnits),
		RiskFamilyCount: len(families), ContributingFamilies: len(contributions),
		PathCount: len(pathIDs), PathIDs: pathIDs, RiskFamilyIDs: familyIDs,
		Contributions: contributions,
		Explanation: fmt.Sprintf(
			"highest root-cause family plus ranked semantically distinct families at %s%%, capped at +%d; duplicate outcome sets do not contribute twice",
			joinInts(additionalFamilyWeightsPercent), maxFamilyDiversityContribution),
	}
}

type familyBuilder struct {
	value       Family
	paths       []PathScore
	pathIDs     map[string]struct{}
	riskUnits   map[string]struct{}
	grantIDs    map[string]struct{}
	templateIDs map[string]struct{}
	targetTypes map[attackpath.PrivilegeTargetType]struct{}
}

func buildRiskFamilies(paths []PathScore) []Family {
	builders := make(map[string]*familyBuilder)
	for _, path := range paths {
		key := path.RootCauseKey
		if key == "" {
			key = "path|" + path.Source.String() + "|" + path.RiskUnit
		}
		builder, found := builders[key]
		if !found {
			id := path.RiskFamilyID
			if id == "" {
				id = stableID("family", key)
			}
			builder = &familyBuilder{
				value: Family{
					ID: id, RootCauseKey: key, RootCause: path.RootCause,
					Source: path.Source, BindingRef: path.BindingRef, RoleRef: path.RoleRef,
				},
				pathIDs: make(map[string]struct{}), riskUnits: make(map[string]struct{}),
				grantIDs: make(map[string]struct{}), templateIDs: make(map[string]struct{}),
				targetTypes: make(map[attackpath.PrivilegeTargetType]struct{}),
			}
			builders[key] = builder
		}
		builder.paths = append(builder.paths, path)
		builder.pathIDs[path.PathID] = struct{}{}
		builder.riskUnits[path.RiskUnit] = struct{}{}
		builder.templateIDs[path.TemplateID] = struct{}{}
		builder.targetTypes[path.Target.Type] = struct{}{}
		for _, grantID := range path.GrantIDs {
			builder.grantIDs[grantID] = struct{}{}
		}
	}

	result := make([]Family, 0, len(builders))
	for _, builder := range builders {
		sort.Slice(builder.paths, func(i, j int) bool {
			if builder.paths[i].Score != builder.paths[j].Score {
				return builder.paths[i].Score > builder.paths[j].Score
			}
			return builder.paths[i].PathID < builder.paths[j].PathID
		})
		primary := builder.paths[0]
		builder.value.Score = primary.Score
		builder.value.Severity = primary.Severity
		builder.value.Confidence = primary.Confidence
		builder.value.PrimaryPathID = primary.PathID
		builder.value.PrimaryRiskUnit = primary.RiskUnit
		builder.value.PathIDs = sortedStringKeys(builder.pathIDs)
		builder.value.RiskUnits = sortedStringKeys(builder.riskUnits)
		builder.value.GrantIDs = sortedStringKeys(builder.grantIDs)
		builder.value.TemplateIDs = sortedStringKeys(builder.templateIDs)
		builder.value.PathCount = len(builder.value.PathIDs)
		builder.value.DistinctRiskUnits = len(builder.value.RiskUnits)
		builder.value.SemanticKey = stableID("semantic", strings.Join(builder.value.RiskUnits, "\x00"))
		builder.value.Blocked = true
		for _, path := range builder.paths {
			if !path.Blocked {
				builder.value.Blocked = false
				break
			}
		}
		for targetType := range builder.targetTypes {
			builder.value.TargetTypes = append(builder.value.TargetTypes, targetType)
		}
		sort.Slice(builder.value.TargetTypes, func(i, j int) bool {
			return builder.value.TargetTypes[i] < builder.value.TargetTypes[j]
		})
		result = append(result, builder.value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func sortedStringKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, "/")
}

func sortAggregates(values []AggregateScore) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Score != values[j].Score {
			return values[i].Score > values[j].Score
		}
		return values[i].Key < values[j].Key
	})
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	write := 0
	for _, value := range values {
		if write == 0 || values[write-1] != value {
			values[write] = value
			write++
		}
	}
	return values[:write]
}
