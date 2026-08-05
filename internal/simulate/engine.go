package simulate

import (
	"context"
	"fmt"

	"github.com/rbacviz/rbacviz/internal/diff"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// Run overlays all manifests in source/document order and compares the result
// with the immutable base snapshot. It performs no network calls.
func Run(ctx context.Context, baseInput snapshot.Snapshot, manifests []Manifest, options Options) (Result, error) {
	base, err := snapshot.Canonicalize(baseInput)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize simulation base: %w", err)
	}
	if len(manifests) == 0 {
		return Result{}, fmt.Errorf("at least one manifest is required")
	}
	simulated := base
	applied := make([]AppliedChange, 0, len(manifests))
	for _, manifest := range manifests {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		existed, err := applyManifest(&simulated, manifest)
		if err != nil {
			return Result{}, fmt.Errorf("apply %s document %d: %w", manifest.Source, manifest.Document, err)
		}
		applied = append(applied, AppliedChange{
			Source: manifest.Source, Document: manifest.Document, Operation: manifest.Operation,
			Ref: manifest.Ref, Category: manifest.Category, Existed: existed,
		})
	}
	// Identities are derived inventory from current bindings and
	// ServiceAccounts. Rebuild it so removed or replaced subjects do not remain
	// as stale simulation artifacts.
	simulated.Identities = nil
	simulated, err = snapshot.Canonicalize(simulated)
	if err != nil {
		return Result{}, fmt.Errorf("canonicalize simulated snapshot: %w", err)
	}
	comparison, err := diff.Compare(ctx, base, simulated, options.Diff)
	if err != nil {
		return Result{}, fmt.Errorf("compare simulated snapshot: %w", err)
	}
	return Result{
		SchemaVersion: ResultSchemaVersion, BaseDigest: comparison.BeforeSemanticDigest,
		SimulatedDigest: comparison.AfterSemanticDigest, Applied: applied, Diff: comparison,
	}, nil
}

func applyManifest(value *snapshot.Snapshot, manifest Manifest) (bool, error) {
	switch manifest.Category {
	case "role":
		item, ok := manifest.object.(snapshot.Role)
		if manifest.Operation == OperationUpsert && !ok {
			return false, fmt.Errorf("manifest does not contain a role overlay")
		}
		return applyRole(&value.Roles, manifest, item), nil
	case "binding":
		item, ok := manifest.object.(snapshot.Binding)
		if manifest.Operation == OperationUpsert && !ok {
			return false, fmt.Errorf("manifest does not contain a binding overlay")
		}
		return applyBinding(&value.Bindings, manifest, item), nil
	case "serviceAccount":
		item, ok := manifest.object.(snapshot.ServiceAccount)
		if manifest.Operation == OperationUpsert && !ok {
			return false, fmt.Errorf("manifest does not contain a ServiceAccount overlay")
		}
		return applyServiceAccount(&value.ServiceAccounts, manifest, item), nil
	case "workload":
		item, ok := manifest.object.(snapshot.Workload)
		if manifest.Operation == OperationUpsert && !ok {
			return false, fmt.Errorf("manifest does not contain a workload overlay")
		}
		return applyWorkload(&value.Workloads, manifest, item), nil
	case "asset":
		item, ok := manifest.object.(snapshot.Asset)
		if manifest.Operation == OperationUpsert && !ok {
			return false, fmt.Errorf("manifest does not contain an asset overlay")
		}
		return applyAsset(&value.Assets, manifest, item), nil
	case "namespace":
		return applyNamespace(&value.SecurityControls, manifest)
	case "securityControl":
		item, ok := manifest.object.(snapshot.SecurityControl)
		if manifest.Operation == OperationUpsert && !ok {
			return false, fmt.Errorf("manifest does not contain a security-control overlay")
		}
		return applyControl(&value.SecurityControls, manifest, item), nil
	default:
		return false, fmt.Errorf("unsupported overlay category %q", manifest.Category)
	}
}

func applyRole(values *[]snapshot.Role, manifest Manifest, item snapshot.Role) bool {
	index := findRole(*values, manifest.Ref)
	existed := index >= 0
	if manifest.Operation == OperationDelete {
		if existed {
			*values = append((*values)[:index], (*values)[index+1:]...)
		}
		return existed
	}
	if existed {
		preserveUID(&item.Ref, (*values)[index].Ref)
		(*values)[index] = item
	} else {
		*values = append(*values, item)
	}
	return existed
}

func applyBinding(values *[]snapshot.Binding, manifest Manifest, item snapshot.Binding) bool {
	index := findBinding(*values, manifest.Ref)
	existed := index >= 0
	if manifest.Operation == OperationDelete {
		if existed {
			*values = append((*values)[:index], (*values)[index+1:]...)
		}
		return existed
	}
	if existed {
		preserveUID(&item.Ref, (*values)[index].Ref)
		(*values)[index] = item
	} else {
		*values = append(*values, item)
	}
	return existed
}

func applyServiceAccount(values *[]snapshot.ServiceAccount, manifest Manifest, item snapshot.ServiceAccount) bool {
	index := findServiceAccount(*values, manifest.Ref)
	existed := index >= 0
	if manifest.Operation == OperationDelete {
		if existed {
			*values = append((*values)[:index], (*values)[index+1:]...)
		}
		return existed
	}
	if existed {
		preserveUID(&item.Ref, (*values)[index].Ref)
		(*values)[index] = item
	} else {
		*values = append(*values, item)
	}
	return existed
}

func applyWorkload(values *[]snapshot.Workload, manifest Manifest, item snapshot.Workload) bool {
	index := findWorkload(*values, manifest.Ref)
	existed := index >= 0
	if manifest.Operation == OperationDelete {
		if existed {
			*values = append((*values)[:index], (*values)[index+1:]...)
		}
		return existed
	}
	if existed {
		preserveUID(&item.Ref, (*values)[index].Ref)
		(*values)[index] = item
	} else {
		*values = append(*values, item)
	}
	return existed
}

func applyAsset(values *[]snapshot.Asset, manifest Manifest, item snapshot.Asset) bool {
	index := findAsset(*values, manifest.Ref)
	existed := index >= 0
	if manifest.Operation == OperationDelete {
		if existed {
			*values = append((*values)[:index], (*values)[index+1:]...)
		}
		return existed
	}
	if existed {
		preserveUID(&item.Ref, (*values)[index].Ref)
		(*values)[index] = item
	} else {
		*values = append(*values, item)
	}
	return existed
}

func applyControl(values *[]snapshot.SecurityControl, manifest Manifest, item snapshot.SecurityControl) bool {
	index := findControl(*values, manifest.Ref, item.ControlType)
	existed := index >= 0
	if manifest.Operation == OperationDelete {
		// Delete by object ref because a delete manifest does not need to carry
		// enough spec to derive a control type.
		indexes := matchingControlIndexes(*values, manifest.Ref)
		if len(indexes) > 0 {
			removeControlIndexes(values, indexes)
			return true
		}
		return false
	}
	if existed {
		preserveUID(&item.Ref, (*values)[index].Ref)
		(*values)[index] = item
	} else {
		*values = append(*values, item)
	}
	return existed
}

func applyNamespace(values *[]snapshot.SecurityControl, manifest Manifest) (bool, error) {
	indexes := matchingControlIndexes(*values, manifest.Ref)
	existed := len(indexes) > 0
	if len(indexes) > 0 {
		removeControlIndexes(values, indexes)
	}
	if manifest.Operation == OperationDelete {
		return existed, nil
	}
	overlay, ok := manifest.object.(namespaceOverlay)
	if !ok {
		return false, fmt.Errorf("manifest does not contain a Namespace overlay")
	}
	if overlay.control != nil {
		control := *overlay.control
		if existed && control.Ref.UID == "" {
			// UID is not material to PSA semantics; an existing namespace UID is
			// unavailable after removing the prior control and may remain empty.
			control.Ref.UID = manifest.Ref.UID
		}
		*values = append(*values, control)
	}
	return existed, nil
}

func matchingControlIndexes(values []snapshot.SecurityControl, ref snapshot.ObjectRef) []int {
	result := []int{}
	for index, item := range values {
		if sameRef(item.Ref, ref) {
			result = append(result, index)
		}
	}
	return result
}

func removeControlIndexes(values *[]snapshot.SecurityControl, indexes []int) {
	wanted := make(map[int]struct{}, len(indexes))
	for _, index := range indexes {
		wanted[index] = struct{}{}
	}
	result := make([]snapshot.SecurityControl, 0, len(*values)-len(indexes))
	for index, item := range *values {
		if _, remove := wanted[index]; !remove {
			result = append(result, item)
		}
	}
	*values = result
}

func findRole(values []snapshot.Role, ref snapshot.ObjectRef) int {
	for index, item := range values {
		if sameRef(item.Ref, ref) {
			return index
		}
	}
	return -1
}

func findBinding(values []snapshot.Binding, ref snapshot.ObjectRef) int {
	for index, item := range values {
		if sameRef(item.Ref, ref) {
			return index
		}
	}
	return -1
}

func findServiceAccount(values []snapshot.ServiceAccount, ref snapshot.ObjectRef) int {
	for index, item := range values {
		if sameRef(item.Ref, ref) {
			return index
		}
	}
	return -1
}

func findWorkload(values []snapshot.Workload, ref snapshot.ObjectRef) int {
	for index, item := range values {
		if sameRef(item.Ref, ref) {
			return index
		}
	}
	return -1
}

func findAsset(values []snapshot.Asset, ref snapshot.ObjectRef) int {
	for index, item := range values {
		if sameRef(item.Ref, ref) {
			return index
		}
	}
	return -1
}

func findControl(values []snapshot.SecurityControl, ref snapshot.ObjectRef, controlType string) int {
	for index, item := range values {
		if sameRef(item.Ref, ref) && item.ControlType == controlType {
			return index
		}
	}
	return -1
}

func sameRef(left, right snapshot.ObjectRef) bool { return refKey(left) == refKey(right) }

func refKey(value snapshot.ObjectRef) string {
	return value.APIGroup + "\x00" + value.Kind + "\x00" + value.Namespace + "\x00" + value.Name
}

func preserveUID(target *snapshot.ObjectRef, current snapshot.ObjectRef) {
	if target.UID == "" {
		target.UID = current.UID
	}
}
