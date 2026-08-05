package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type workloadMatch struct {
	field  string
	values func(snapshot.Workload) []string
}

type workloadRule struct {
	metadata RuleMetadata
	match    workloadMatch
}

func (rule workloadRule) Metadata() RuleMetadata { return rule.metadata }

func (rule workloadRule) Evaluate(ctx context.Context, input EvaluationContext) ([]Finding, error) {
	result := make([]Finding, 0)
	for _, workload := range input.Snapshot.Workloads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, value := range rule.match.values(workload) {
			result = append(result, Finding{
				Confidence:      ConfidenceConfirmed,
				Description:     fmt.Sprintf("%s: %s %s has %s=%s.", rule.metadata.Description, workload.Ref.Kind, qualifiedRef(workload.Ref), rule.match.field, value),
				AffectedObjects: []snapshot.ObjectRef{workload.Ref}, AffectedIdentities: nil,
				Evidence:      []Evidence{{Kind: "ObjectField", Ref: refPointer(workload.Ref), Field: rule.match.field, Value: value}},
				Preconditions: []string{}, MitigatingControls: []string{}, AttackPaths: []string{},
				fingerprint: objectKey(workload.Ref) + "\x00" + rule.match.field + "\x00" + value,
			})
		}
	}
	return result, nil
}

func boolWorkloadField(field string, read func(snapshot.Workload) bool) workloadMatch {
	return workloadMatch{field: field, values: func(value snapshot.Workload) []string {
		if read(value) {
			return []string{"true"}
		}
		return nil
	}}
}

func privilegedContainers(value snapshot.Workload) []string {
	return append([]string(nil), value.PrivilegedContainers...)
}

func hostPathVolumes(value snapshot.Workload) []string {
	result := make([]string, 0)
	for _, volume := range value.Volumes {
		if strings.EqualFold(volume.Kind, "HostPath") {
			detail := volume.Name
			if volume.Target != "" {
				detail += ":" + volume.Target
			}
			result = append(result, detail)
		}
	}
	return result
}
