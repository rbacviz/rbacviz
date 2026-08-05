package collector

import (
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func objectRef(apiGroup, kind string, metadata metav1.Object) snapshot.ObjectRef {
	return snapshot.ObjectRef{APIGroup: apiGroup, Kind: kind, Namespace: metadata.GetNamespace(), Name: metadata.GetName(), UID: string(metadata.GetUID())}
}

func labels(values map[string]string) []snapshot.KeyValue {
	result := make([]snapshot.KeyValue, 0, len(values))
	for key, value := range values {
		result = append(result, snapshot.KeyValue{Key: key, Value: value})
	}
	return result
}

func policyRules(values []rbacv1.PolicyRule) []snapshot.PolicyRule {
	result := make([]snapshot.PolicyRule, 0, len(values))
	for _, rule := range values {
		result = append(result, snapshot.PolicyRule{
			Verbs:           append([]string(nil), rule.Verbs...),
			APIGroups:       append([]string(nil), rule.APIGroups...),
			Resources:       append([]string(nil), rule.Resources...),
			ResourceNames:   append([]string(nil), rule.ResourceNames...),
			NonResourceURLs: append([]string(nil), rule.NonResourceURLs...),
		})
	}
	return result
}

func aggregationSelectors(rule *rbacv1.AggregationRule) []snapshot.LabelSelector {
	if rule == nil {
		return nil
	}
	result := make([]snapshot.LabelSelector, 0, len(rule.ClusterRoleSelectors))
	for _, selector := range rule.ClusterRoleSelectors {
		converted := snapshot.LabelSelector{MatchLabels: labels(selector.MatchLabels)}
		for _, expression := range selector.MatchExpressions {
			converted.MatchExpressions = append(converted.MatchExpressions, snapshot.SelectorRequirement{
				Key: expression.Key, Operator: string(expression.Operator), Values: append([]string(nil), expression.Values...),
			})
		}
		result = append(result, converted)
	}
	return result
}

func subjects(values []rbacv1.Subject, bindingNamespace string) []snapshot.Subject {
	result := make([]snapshot.Subject, 0, len(values))
	for _, subject := range values {
		namespace := subject.Namespace
		if subject.Kind == rbacv1.ServiceAccountKind && namespace == "" {
			namespace = bindingNamespace
		}
		result = append(result, snapshot.Subject{Kind: snapshot.IdentityKind(subject.Kind), APIGroup: subject.APIGroup, Namespace: namespace, Name: subject.Name})
	}
	return result
}

func owners(values []metav1.OwnerReference, namespace string) []snapshot.OwnerReference {
	result := make([]snapshot.OwnerReference, 0, len(values))
	for _, owner := range values {
		controller := owner.Controller != nil && *owner.Controller
		result = append(result, snapshot.OwnerReference{Ref: snapshot.ObjectRef{APIGroup: groupFromAPIVersion(owner.APIVersion), Kind: owner.Kind, Namespace: namespace, Name: owner.Name, UID: string(owner.UID)}, Controller: controller})
	}
	return result
}

func groupFromAPIVersion(apiVersion string) string {
	for index, character := range apiVersion {
		if character == '/' {
			return apiVersion[:index]
		}
	}
	return ""
}

func workload(ref snapshot.ObjectRef, metadata metav1.Object, spec corev1.PodSpec) snapshot.Workload {
	result := snapshot.Workload{
		Ref: ref, Labels: labels(metadata.GetLabels()), Owners: owners(metadata.GetOwnerReferences(), metadata.GetNamespace()),
		ServiceAccountName: spec.ServiceAccountName, AutomountServiceToken: spec.AutomountServiceAccountToken,
		HostNetwork: spec.HostNetwork, HostPID: spec.HostPID, HostIPC: spec.HostIPC,
	}
	if result.ServiceAccountName == "" {
		result.ServiceAccountName = "default"
	}
	for _, container := range append(append([]corev1.Container(nil), spec.InitContainers...), spec.Containers...) {
		if container.Image != "" {
			result.Images = append(result.Images, container.Image)
		}
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			result.PrivilegedContainers = append(result.PrivilegedContainers, container.Name)
		}
	}
	for _, container := range spec.EphemeralContainers {
		if container.Image != "" {
			result.Images = append(result.Images, container.Image)
		}
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			result.PrivilegedContainers = append(result.PrivilegedContainers, container.Name)
		}
	}
	for _, volume := range spec.Volumes {
		switch {
		case volume.Secret != nil:
			result.Volumes = append(result.Volumes, snapshot.VolumeReference{Name: volume.Name, Kind: "Secret", Namespace: metadata.GetNamespace(), Target: volume.Secret.SecretName})
		case volume.ConfigMap != nil:
			result.Volumes = append(result.Volumes, snapshot.VolumeReference{Name: volume.Name, Kind: "ConfigMap", Namespace: metadata.GetNamespace(), Target: volume.ConfigMap.Name})
		case volume.HostPath != nil:
			result.Volumes = append(result.Volumes, snapshot.VolumeReference{Name: volume.Name, Kind: "HostPath", Namespace: metadata.GetNamespace(), Target: volume.HostPath.Path})
		case volume.Projected != nil:
			for sourceIndex, source := range volume.Projected.Sources {
				name := volume.Name + "/" + strconv.Itoa(sourceIndex)
				switch {
				case source.Secret != nil:
					result.Volumes = append(result.Volumes, snapshot.VolumeReference{Name: name, Kind: "Secret", Namespace: metadata.GetNamespace(), Target: source.Secret.Name})
				case source.ConfigMap != nil:
					result.Volumes = append(result.Volumes, snapshot.VolumeReference{Name: name, Kind: "ConfigMap", Namespace: metadata.GetNamespace(), Target: source.ConfigMap.Name})
				case source.ServiceAccountToken != nil:
					result.Volumes = append(result.Volumes, snapshot.VolumeReference{Name: name, Kind: "ServiceAccountToken", Namespace: metadata.GetNamespace(), Target: result.ServiceAccountName})
				}
			}
		}
	}
	return result
}

func deploymentWorkload(value *appsv1.Deployment) snapshot.Workload {
	return workload(objectRef("apps", "Deployment", value), value, value.Spec.Template.Spec)
}
func daemonSetWorkload(value *appsv1.DaemonSet) snapshot.Workload {
	return workload(objectRef("apps", "DaemonSet", value), value, value.Spec.Template.Spec)
}
func statefulSetWorkload(value *appsv1.StatefulSet) snapshot.Workload {
	return workload(objectRef("apps", "StatefulSet", value), value, value.Spec.Template.Spec)
}
func jobWorkload(value *batchv1.Job) snapshot.Workload {
	return workload(objectRef("batch", "Job", value), value, value.Spec.Template.Spec)
}
func cronJobWorkload(value *batchv1.CronJob) snapshot.Workload {
	return workload(objectRef("batch", "CronJob", value), value, value.Spec.JobTemplate.Spec.Template.Spec)
}
