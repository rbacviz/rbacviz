package permission

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type ruleOrigin struct {
	rule   snapshot.PolicyRule
	source snapshot.ObjectRef
	chain  []snapshot.ObjectRef
}

func (resolver *Resolver) buildAggregates() {
	dependencies := make(map[string][]string)
	for key, role := range resolver.roles {
		if role.Ref.Kind != "ClusterRole" || len(role.AggregationSelectors) == 0 {
			continue
		}
		selected := make(map[string]struct{})
		for _, portable := range role.AggregationSelectors {
			selector, err := labelSelector(portable)
			if err != nil {
				resolver.addWarning(Warning{Code: "InvalidAggregationSelector", Message: fmt.Sprintf("ClusterRole %s has an invalid aggregation selector: %v", role.Ref.Name, err), Ref: role.Ref})
				continue
			}
			for candidateKey, candidate := range resolver.roles {
				if candidate.Ref.Kind != "ClusterRole" {
					continue
				}
				if selector.Matches(labels.Set(pairMap(candidate.Labels))) {
					selected[candidateKey] = struct{}{}
				}
			}
		}
		for selectedKey := range selected {
			dependencies[key] = append(dependencies[key], selectedKey)
		}
		sort.Strings(dependencies[key])
	}
	resolver.detectAggregationCycles(dependencies)

	for key, role := range resolver.roles {
		// The Kubernetes aggregation controller owns rules on an aggregated
		// ClusterRole. Recompute them from selectors so stale materialized rules
		// cannot create phantom grants in an offline snapshot.
		if len(role.AggregationSelectors) > 0 && role.Ref.Kind == "ClusterRole" {
			resolver.effectiveRules[key] = []ruleOrigin{}
			continue
		}
		for _, rule := range role.Rules {
			resolver.effectiveRules[key] = append(resolver.effectiveRules[key], ruleOrigin{rule: rule, source: role.Ref})
		}
	}

	changed := true
	for changed {
		changed = false
		keys := sortedMapKeys(dependencies)
		for _, targetKey := range keys {
			target := resolver.roles[targetKey]
			for _, dependencyKey := range dependencies[targetKey] {
				dependency := resolver.roles[dependencyKey]
				for _, origin := range resolver.effectiveRules[dependencyKey] {
					chain, cyclic := prependAggregation(target.Ref, dependency.Ref, origin.chain)
					if cyclic {
						continue
					}
					candidate := ruleOrigin{rule: origin.rule, source: origin.source, chain: chain}
					updated, added := appendUniqueOrigin(resolver.effectiveRules[targetKey], candidate)
					if added {
						resolver.effectiveRules[targetKey] = updated
						changed = true
					}
				}
			}
		}
	}
	for key := range resolver.effectiveRules {
		sort.Slice(resolver.effectiveRules[key], func(i, j int) bool {
			return originKey(resolver.effectiveRules[key][i]) < originKey(resolver.effectiveRules[key][j])
		})
	}
}

func labelSelector(value snapshot.LabelSelector) (labels.Selector, error) {
	portable := &metav1.LabelSelector{MatchLabels: pairMap(value.MatchLabels)}
	for _, expression := range value.MatchExpressions {
		portable.MatchExpressions = append(portable.MatchExpressions, metav1.LabelSelectorRequirement{
			Key: expression.Key, Operator: metav1.LabelSelectorOperator(expression.Operator), Values: append([]string(nil), expression.Values...),
		})
	}
	return metav1.LabelSelectorAsSelector(portable)
}

func pairMap(values []snapshot.KeyValue) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value.Key] = value.Value
	}
	return result
}

func prependAggregation(target, dependency snapshot.ObjectRef, existing []snapshot.ObjectRef) ([]snapshot.ObjectRef, bool) {
	if sameRef(target, dependency) {
		return nil, true
	}
	if len(existing) == 0 {
		return []snapshot.ObjectRef{target, dependency}, false
	}
	for _, ref := range existing {
		if sameRef(target, ref) {
			return nil, true
		}
	}
	result := make([]snapshot.ObjectRef, 0, len(existing)+1)
	result = append(result, target)
	result = append(result, existing...)
	return result, false
}

func appendUniqueOrigin(values []ruleOrigin, candidate ruleOrigin) ([]ruleOrigin, bool) {
	key := originKey(candidate)
	for _, existing := range values {
		if originKey(existing) == key {
			return values, false
		}
	}
	return append(values, candidate), true
}

func originKey(value ruleOrigin) string {
	parts := []string{value.rule.ID, refKey(value.source)}
	for _, ref := range value.chain {
		parts = append(parts, refKey(ref))
	}
	return strings.Join(parts, "|")
}

func (resolver *Resolver) detectAggregationCycles(dependencies map[string][]string) {
	state := make(map[string]uint8)
	stack := make([]string, 0)
	var visit func(string)
	visit = func(key string) {
		state[key] = 1
		stack = append(stack, key)
		for _, dependency := range dependencies[key] {
			switch state[dependency] {
			case 0:
				visit(dependency)
			case 1:
				cycle := cycleNames(stack, dependency, resolver.roles)
				resolver.addWarning(Warning{Code: "AggregationCycle", Message: "ClusterRole aggregation cycle: " + strings.Join(cycle, " -> "), Ref: resolver.roles[key].Ref})
			}
		}
		stack = stack[:len(stack)-1]
		state[key] = 2
	}
	for _, key := range sortedMapKeys(dependencies) {
		if state[key] == 0 {
			visit(key)
		}
	}
}

func cycleNames(stack []string, start string, roles map[string]snapshot.Role) []string {
	index := 0
	for index < len(stack) && stack[index] != start {
		index++
	}
	result := make([]string, 0, len(stack)-index+1)
	for _, key := range stack[index:] {
		result = append(result, roles[key].Ref.Name)
	}
	result = append(result, roles[start].Ref.Name)
	return result
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
