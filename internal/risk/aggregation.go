package risk

import (
	"fmt"
	"sort"

	"github.com/rbacviz/rbacviz/internal/permission"
)

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

func aggregate(kind AggregateKind, key string, identity *permission.Identity, namespace string, paths []PathScore) AggregateScore {
	pathIDs := make([]string, 0, len(paths))
	units := make(map[string]PathScore)
	for _, path := range paths {
		pathIDs = append(pathIDs, path.PathID)
		current, found := units[path.RiskUnit]
		if !found || path.Score > current.Score || (path.Score == current.Score && path.PathID < current.PathID) {
			units[path.RiskUnit] = path
		}
	}
	sort.Strings(pathIDs)
	pathIDs = uniqueStrings(pathIDs)
	unitScores := make([]PathScore, 0, len(units))
	for _, path := range units {
		unitScores = append(unitScores, path)
	}
	sort.Slice(unitScores, func(i, j int) bool {
		if unitScores[i].Score != unitScores[j].Score {
			return unitScores[i].Score > unitScores[j].Score
		}
		return unitScores[i].RiskUnit < unitScores[j].RiskUnit
	})

	primary, current := 0, 0
	if len(unitScores) > 0 {
		primary = unitScores[0].Score
		current = primary
		for _, value := range unitScores[1:] {
			headroom := 100 - current
			delta := roundDivide(int64(headroom*value.Score*additionalRiskRatePercent), 10000)
			current = clamp(current + delta)
		}
	}
	return AggregateScore{
		Kind: kind, Key: key, Identity: identity, Namespace: namespace,
		Score: current, Severity: severity(current), PrimaryScore: primary,
		AdditionalContribution: current - primary, DistinctRiskUnits: len(unitScores),
		PathCount: len(pathIDs), PathIDs: pathIDs,
		Explanation: fmt.Sprintf("maximum distinct risk unit plus %d%% of each additional unit's score applied to remaining headroom", additionalRiskRatePercent),
	}
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
