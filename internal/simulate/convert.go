package simulate

import (
	"fmt"
	"strconv"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type namespaceOverlay struct {
	control *snapshot.SecurityControl
}

func convertObject(source string, document int, value *unstructured.Unstructured, defaultNamespace string) (Manifest, error) {
	apiVersion := strings.TrimSpace(value.GetAPIVersion())
	kind := strings.TrimSpace(value.GetKind())
	name := strings.TrimSpace(value.GetName())
	if apiVersion == "" || kind == "" || name == "" {
		return Manifest{}, fmt.Errorf("manifest %q document %d requires apiVersion, kind, and metadata.name", source, document)
	}
	operation := OperationUpsert
	if raw := strings.ToLower(strings.TrimSpace(value.GetAnnotations()[OperationAnnotation])); raw != "" {
		switch raw {
		case "delete":
			operation = OperationDelete
		case "upsert", "replace":
			operation = OperationUpsert
		default:
			return Manifest{}, fmt.Errorf("manifest %q document %d has unsupported %s value %q", source, document, OperationAnnotation, raw)
		}
	}
	if value.GetNamespace() == "" && isNamespacedKind(apiGroup(apiVersion), kind) {
		if defaultNamespace == "" {
			defaultNamespace = "default"
		}
		value.SetNamespace(defaultNamespace)
	}
	ref := snapshot.ObjectRef{APIGroup: apiGroup(apiVersion), Kind: kind, Namespace: value.GetNamespace(), Name: name, UID: string(value.GetUID())}
	category, err := categoryFor(ref)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest %q document %d: %w", source, document, err)
	}
	manifest := Manifest{Source: source, Document: document, Operation: operation, Ref: ref, Category: category}
	if operation == OperationDelete {
		return manifest, nil
	}
	converted, err := convertRelevantObject(value, ref, category)
	if err != nil {
		return Manifest{}, fmt.Errorf("convert manifest %q document %d %s %s: %w", source, document, kind, name, err)
	}
	manifest.object = converted
	return manifest, nil
}

func categoryFor(ref snapshot.ObjectRef) (string, error) {
	switch ref.Kind {
	case "Role", "ClusterRole":
		if ref.APIGroup == rbacv1.GroupName {
			return "role", nil
		}
	case "RoleBinding", "ClusterRoleBinding":
		if ref.APIGroup == rbacv1.GroupName {
			return "binding", nil
		}
	case "ServiceAccount":
		return "serviceAccount", nil
	case "Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob":
		return "workload", nil
	case "Secret", "ConfigMap", "Node", "PersistentVolume", "PersistentVolumeClaim", "CertificateSigningRequest", "Ingress", "Service":
		return "asset", nil
	case "Namespace":
		return "namespace", nil
	case "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration":
		if ref.APIGroup == admissionv1.GroupName {
			return "securityControl", nil
		}
	}
	if isExternalPolicy(ref.APIGroup, ref.Kind) {
		return "securityControl", nil
	}
	return "", fmt.Errorf("unsupported manifest kind %s/%s", ref.APIGroup, ref.Kind)
}

func convertRelevantObject(value *unstructured.Unstructured, ref snapshot.ObjectRef, category string) (any, error) {
	switch category {
	case "role":
		return convertRole(value, ref)
	case "binding":
		return convertBinding(value, ref)
	case "serviceAccount":
		var typed corev1.ServiceAccount
		if err := fromUnstructured(value, &typed); err != nil {
			return nil, err
		}
		return snapshot.ServiceAccount{Ref: ref, Labels: labels(typed.Labels), AutomountServiceToken: typed.AutomountServiceAccountToken}, nil
	case "workload":
		return convertWorkload(value, ref)
	case "asset":
		return convertAsset(value, ref)
	case "namespace":
		var typed corev1.Namespace
		if err := fromUnstructured(value, &typed); err != nil {
			return nil, err
		}
		details := []snapshot.KeyValue{}
		for key, item := range typed.Labels {
			if strings.HasPrefix(key, "pod-security.kubernetes.io/") {
				details = append(details, snapshot.KeyValue{Key: key, Value: item})
			}
		}
		if len(details) == 0 {
			return namespaceOverlay{}, nil
		}
		control := snapshot.SecurityControl{Ref: ref, ControlType: "PodSecurityAdmission", Mode: typed.Labels["pod-security.kubernetes.io/enforce"], Details: details}
		return namespaceOverlay{control: &control}, nil
	case "securityControl":
		return convertControl(value, ref)
	default:
		return nil, fmt.Errorf("unsupported category %q", category)
	}
}

func convertRole(value *unstructured.Unstructured, ref snapshot.ObjectRef) (snapshot.Role, error) {
	if ref.Kind == "Role" {
		var typed rbacv1.Role
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Role{}, err
		}
		return snapshot.Role{Ref: ref, Labels: labels(typed.Labels), Rules: policyRules(typed.Rules)}, nil
	}
	var typed rbacv1.ClusterRole
	if err := fromUnstructured(value, &typed); err != nil {
		return snapshot.Role{}, err
	}
	return snapshot.Role{Ref: ref, Labels: labels(typed.Labels), Rules: policyRules(typed.Rules), AggregationSelectors: aggregationSelectors(typed.AggregationRule)}, nil
}

func convertBinding(value *unstructured.Unstructured, ref snapshot.ObjectRef) (snapshot.Binding, error) {
	if ref.Kind == "RoleBinding" {
		var typed rbacv1.RoleBinding
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Binding{}, err
		}
		return snapshot.Binding{Ref: ref, Labels: labels(typed.Labels), RoleRef: roleReference(typed.RoleRef, ref.Namespace), Subjects: subjects(typed.Subjects, ref.Namespace)}, nil
	}
	var typed rbacv1.ClusterRoleBinding
	if err := fromUnstructured(value, &typed); err != nil {
		return snapshot.Binding{}, err
	}
	return snapshot.Binding{Ref: ref, Labels: labels(typed.Labels), RoleRef: roleReference(typed.RoleRef, ""), Subjects: subjects(typed.Subjects, "")}, nil
}

func convertWorkload(value *unstructured.Unstructured, ref snapshot.ObjectRef) (snapshot.Workload, error) {
	switch ref.Kind {
	case "Pod":
		var typed corev1.Pod
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Workload{}, err
		}
		return workload(ref, &typed.ObjectMeta, typed.Spec), nil
	case "Deployment":
		var typed appsv1.Deployment
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Workload{}, err
		}
		return workload(ref, &typed.ObjectMeta, typed.Spec.Template.Spec), nil
	case "DaemonSet":
		var typed appsv1.DaemonSet
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Workload{}, err
		}
		return workload(ref, &typed.ObjectMeta, typed.Spec.Template.Spec), nil
	case "StatefulSet":
		var typed appsv1.StatefulSet
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Workload{}, err
		}
		return workload(ref, &typed.ObjectMeta, typed.Spec.Template.Spec), nil
	case "Job":
		var typed batchv1.Job
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Workload{}, err
		}
		return workload(ref, &typed.ObjectMeta, typed.Spec.Template.Spec), nil
	case "CronJob":
		var typed batchv1.CronJob
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Workload{}, err
		}
		return workload(ref, &typed.ObjectMeta, typed.Spec.JobTemplate.Spec.Template.Spec), nil
	default:
		return snapshot.Workload{}, fmt.Errorf("unsupported workload kind %q", ref.Kind)
	}
}

func convertAsset(value *unstructured.Unstructured, ref snapshot.ObjectRef) (snapshot.Asset, error) {
	assetTypes := map[string]string{
		"Secret": "secret", "ConfigMap": "config-map", "Node": "node", "PersistentVolume": "persistent-volume",
		"PersistentVolumeClaim": "persistent-volume-claim", "CertificateSigningRequest": "certificate-signing-request",
		"Ingress": "ingress", "Service": "service",
	}
	result := snapshot.Asset{Ref: ref, Labels: labels(value.GetLabels()), AssetType: assetTypes[ref.Kind]}
	if ref.Kind == "Secret" {
		var typed corev1.Secret
		if err := fromUnstructured(value, &typed); err != nil {
			return snapshot.Asset{}, err
		}
		result.SecretType = string(typed.Type)
	}
	// Convert the remaining kinds once to reject structurally invalid manifests.
	switch ref.Kind {
	case "ConfigMap":
		var typed corev1.ConfigMap
		return result, fromUnstructured(value, &typed)
	case "Node":
		var typed corev1.Node
		return result, fromUnstructured(value, &typed)
	case "PersistentVolume":
		var typed corev1.PersistentVolume
		return result, fromUnstructured(value, &typed)
	case "PersistentVolumeClaim":
		var typed corev1.PersistentVolumeClaim
		return result, fromUnstructured(value, &typed)
	case "CertificateSigningRequest":
		var typed certificatesv1.CertificateSigningRequest
		return result, fromUnstructured(value, &typed)
	case "Ingress":
		var typed networkingv1.Ingress
		return result, fromUnstructured(value, &typed)
	case "Service":
		var typed corev1.Service
		return result, fromUnstructured(value, &typed)
	default:
		return result, nil
	}
}

func convertControl(value *unstructured.Unstructured, ref snapshot.ObjectRef) (snapshot.SecurityControl, error) {
	result := snapshot.SecurityControl{Ref: ref, SemanticsUnknown: true, Details: []snapshot.KeyValue{}}
	switch ref.Kind {
	case "ValidatingAdmissionPolicy":
		var typed admissionv1.ValidatingAdmissionPolicy
		if err := fromUnstructured(value, &typed); err != nil {
			return result, err
		}
		result.ControlType = "ValidatingAdmissionPolicy"
		result.Details = append(result.Details, snapshot.KeyValue{Key: "validations", Value: strconv.Itoa(len(typed.Spec.Validations))}, snapshot.KeyValue{Key: "auditAnnotations", Value: strconv.Itoa(len(typed.Spec.AuditAnnotations))})
		if typed.Spec.FailurePolicy != nil {
			result.Details = append(result.Details, snapshot.KeyValue{Key: "failurePolicy", Value: string(*typed.Spec.FailurePolicy)})
		}
	case "ValidatingAdmissionPolicyBinding":
		var typed admissionv1.ValidatingAdmissionPolicyBinding
		if err := fromUnstructured(value, &typed); err != nil {
			return result, err
		}
		result.ControlType = "ValidatingAdmissionPolicyBinding"
		result.Details = append(result.Details, snapshot.KeyValue{Key: "policyName", Value: typed.Spec.PolicyName})
		for _, action := range typed.Spec.ValidationActions {
			result.Details = append(result.Details, snapshot.KeyValue{Key: "validationAction", Value: string(action)})
		}
	case "ValidatingWebhookConfiguration":
		var typed admissionv1.ValidatingWebhookConfiguration
		if err := fromUnstructured(value, &typed); err != nil {
			return result, err
		}
		result.ControlType = "ValidatingWebhook"
		result.Details = webhookDetails(typed.Webhooks)
	case "MutatingWebhookConfiguration":
		var typed admissionv1.MutatingWebhookConfiguration
		if err := fromUnstructured(value, &typed); err != nil {
			return result, err
		}
		result.ControlType = "MutatingWebhook"
		result.Details = mutatingWebhookDetails(typed.Webhooks)
	default:
		if strings.Contains(ref.APIGroup, "gatekeeper") {
			result.ControlType = "Gatekeeper"
		} else {
			result.ControlType = "Kyverno"
		}
		result.Details = []snapshot.KeyValue{{Key: "resource", Value: strings.ToLower(ref.Kind)}}
	}
	return result, nil
}

func webhookDetails(values []admissionv1.ValidatingWebhook) []snapshot.KeyValue {
	result := []snapshot.KeyValue{{Key: "webhooks", Value: strconv.Itoa(len(values))}}
	for _, item := range values {
		if item.FailurePolicy != nil {
			result = append(result, snapshot.KeyValue{Key: "failurePolicy", Value: string(*item.FailurePolicy)})
		}
	}
	return result
}

func mutatingWebhookDetails(values []admissionv1.MutatingWebhook) []snapshot.KeyValue {
	result := []snapshot.KeyValue{{Key: "webhooks", Value: strconv.Itoa(len(values))}}
	for _, item := range values {
		if item.FailurePolicy != nil {
			result = append(result, snapshot.KeyValue{Key: "failurePolicy", Value: string(*item.FailurePolicy)})
		}
	}
	return result
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
		addContainer(&result, container.Name, container.Image, container.SecurityContext)
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
			for index, source := range volume.Projected.Sources {
				name := volume.Name + "/" + strconv.Itoa(index)
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

func addContainer(result *snapshot.Workload, name, image string, securityContext *corev1.SecurityContext) {
	if image != "" {
		result.Images = append(result.Images, image)
	}
	if securityContext != nil && securityContext.Privileged != nil && *securityContext.Privileged {
		result.PrivilegedContainers = append(result.PrivilegedContainers, name)
	}
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
	for _, item := range values {
		result = append(result, snapshot.PolicyRule{Verbs: append([]string(nil), item.Verbs...), APIGroups: append([]string(nil), item.APIGroups...), Resources: append([]string(nil), item.Resources...), ResourceNames: append([]string(nil), item.ResourceNames...), NonResourceURLs: append([]string(nil), item.NonResourceURLs...)})
	}
	return result
}

func aggregationSelectors(value *rbacv1.AggregationRule) []snapshot.LabelSelector {
	if value == nil {
		return nil
	}
	result := []snapshot.LabelSelector{}
	for _, selector := range value.ClusterRoleSelectors {
		converted := snapshot.LabelSelector{MatchLabels: labels(selector.MatchLabels)}
		for _, expression := range selector.MatchExpressions {
			converted.MatchExpressions = append(converted.MatchExpressions, snapshot.SelectorRequirement{Key: expression.Key, Operator: string(expression.Operator), Values: append([]string(nil), expression.Values...)})
		}
		result = append(result, converted)
	}
	return result
}

func subjects(values []rbacv1.Subject, namespace string) []snapshot.Subject {
	result := make([]snapshot.Subject, 0, len(values))
	for _, item := range values {
		itemNamespace := item.Namespace
		if item.Kind == rbacv1.ServiceAccountKind && itemNamespace == "" {
			itemNamespace = namespace
		}
		result = append(result, snapshot.Subject{Kind: snapshot.IdentityKind(item.Kind), APIGroup: item.APIGroup, Namespace: itemNamespace, Name: item.Name})
	}
	return result
}

func roleReference(value rbacv1.RoleRef, namespace string) snapshot.ObjectRef {
	if value.Kind != "Role" {
		namespace = ""
	}
	return snapshot.ObjectRef{APIGroup: value.APIGroup, Kind: value.Kind, Namespace: namespace, Name: value.Name}
}

func owners(values []metav1.OwnerReference, namespace string) []snapshot.OwnerReference {
	result := make([]snapshot.OwnerReference, 0, len(values))
	for _, item := range values {
		controller := item.Controller != nil && *item.Controller
		result = append(result, snapshot.OwnerReference{Ref: snapshot.ObjectRef{APIGroup: apiGroup(item.APIVersion), Kind: item.Kind, Namespace: namespace, Name: item.Name, UID: string(item.UID)}, Controller: controller})
	}
	return result
}

func fromUnstructured(value *unstructured.Unstructured, target any) error {
	return runtime.DefaultUnstructuredConverter.FromUnstructured(value.Object, target)
}

func apiGroup(apiVersion string) string {
	if index := strings.IndexByte(apiVersion, '/'); index >= 0 {
		return apiVersion[:index]
	}
	return ""
}

func isNamespacedKind(group, kind string) bool {
	if group == rbacv1.GroupName {
		return kind == "Role" || kind == "RoleBinding"
	}
	switch kind {
	case "ServiceAccount", "Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "Secret", "ConfigMap", "PersistentVolumeClaim", "Ingress", "Service":
		return true
	default:
		return group == "kyverno.io" && (kind == "Policy" || kind == "PolicyException")
	}
}

func isExternalPolicy(group, kind string) bool {
	if group == "kyverno.io" {
		return kind == "Policy" || kind == "ClusterPolicy" || kind == "PolicyException"
	}
	return (group == "templates.gatekeeper.sh" && kind == "ConstraintTemplate") || strings.HasPrefix(group, "constraints.gatekeeper.sh")
}
