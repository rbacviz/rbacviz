package collector

import (
	"context"
	"strconv"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func (c *Collector) collectSecurityControls(ctx context.Context, value *snapshot.Snapshot) {
	c.collectPodSecurityAdmission(ctx, value)
	c.collectAdmissionPolicies(ctx, value)
	c.collectAdmissionWebhooks(ctx, value)
	c.collectExternalPolicyMetadata(ctx, value)
}

func (c *Collector) collectPodSecurityAdmission(ctx context.Context, value *snapshot.Snapshot) {
	var namespaces []metav1.Object
	if c.options.Namespace != "" && !c.options.AllNamespaces {
		item, err := c.clients.Kubernetes.CoreV1().Namespaces().Get(ctx, c.options.Namespace, metav1.GetOptions{})
		if err != nil {
			c.warn(value, "namespaces", err)
			return
		}
		namespaces = append(namespaces, item)
	} else {
		items, err := c.clients.Kubernetes.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			c.warn(value, "namespaces", err)
			return
		}
		for index := range items.Items {
			namespaces = append(namespaces, &items.Items[index])
		}
	}
	for _, namespace := range namespaces {
		details := make([]snapshot.KeyValue, 0, 6)
		for key, value := range namespace.GetLabels() {
			if strings.HasPrefix(key, "pod-security.kubernetes.io/") {
				details = append(details, snapshot.KeyValue{Key: key, Value: value})
			}
		}
		if len(details) == 0 {
			continue
		}
		value.SecurityControls = append(value.SecurityControls, snapshot.SecurityControl{
			Ref: objectRef("", "Namespace", namespace), ControlType: "PodSecurityAdmission", Mode: labelValue(namespace.GetLabels(), "pod-security.kubernetes.io/enforce"), Details: details,
		})
	}
}

func (c *Collector) collectAdmissionPolicies(ctx context.Context, value *snapshot.Snapshot) {
	policies, err := c.clients.Kubernetes.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "validatingadmissionpolicies.admissionregistration.k8s.io", err)
	} else {
		for index := range policies.Items {
			policy := &policies.Items[index]
			details := []snapshot.KeyValue{{Key: "validations", Value: strconv.Itoa(len(policy.Spec.Validations))}, {Key: "auditAnnotations", Value: strconv.Itoa(len(policy.Spec.AuditAnnotations))}}
			if policy.Spec.FailurePolicy != nil {
				details = append(details, snapshot.KeyValue{Key: "failurePolicy", Value: string(*policy.Spec.FailurePolicy)})
			}
			if policy.Spec.ParamKind != nil {
				details = append(details, snapshot.KeyValue{Key: "paramKind", Value: policy.Spec.ParamKind.APIVersion + "/" + policy.Spec.ParamKind.Kind})
			}
			value.SecurityControls = append(value.SecurityControls, snapshot.SecurityControl{
				Ref: objectRef(admissionv1.GroupName, "ValidatingAdmissionPolicy", policy), ControlType: "ValidatingAdmissionPolicy", Details: details, SemanticsUnknown: true,
			})
		}
	}
	bindings, err := c.clients.Kubernetes.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "validatingadmissionpolicybindings.admissionregistration.k8s.io", err)
	} else {
		for index := range bindings.Items {
			binding := &bindings.Items[index]
			details := []snapshot.KeyValue{{Key: "policyName", Value: binding.Spec.PolicyName}}
			for _, action := range binding.Spec.ValidationActions {
				details = append(details, snapshot.KeyValue{Key: "validationAction", Value: string(action)})
			}
			if binding.Spec.ParamRef != nil {
				details = append(details, snapshot.KeyValue{Key: "paramName", Value: binding.Spec.ParamRef.Name})
				if binding.Spec.ParamRef.Namespace != "" {
					details = append(details, snapshot.KeyValue{Key: "paramNamespace", Value: binding.Spec.ParamRef.Namespace})
				}
			}
			value.SecurityControls = append(value.SecurityControls, snapshot.SecurityControl{
				Ref: objectRef(admissionv1.GroupName, "ValidatingAdmissionPolicyBinding", binding), ControlType: "ValidatingAdmissionPolicyBinding", Details: details, SemanticsUnknown: true,
			})
		}
	}
}

func (c *Collector) collectAdmissionWebhooks(ctx context.Context, value *snapshot.Snapshot) {
	validating, err := c.clients.Kubernetes.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "validatingwebhookconfigurations.admissionregistration.k8s.io", err)
	} else {
		for index := range validating.Items {
			configuration := &validating.Items[index]
			details := []snapshot.KeyValue{{Key: "webhooks", Value: strconv.Itoa(len(configuration.Webhooks))}}
			for _, webhook := range configuration.Webhooks {
				if webhook.FailurePolicy != nil {
					details = append(details, snapshot.KeyValue{Key: "failurePolicy", Value: string(*webhook.FailurePolicy)})
				}
			}
			value.SecurityControls = append(value.SecurityControls, snapshot.SecurityControl{Ref: objectRef(admissionv1.GroupName, "ValidatingWebhookConfiguration", configuration), ControlType: "ValidatingWebhook", Details: details, SemanticsUnknown: true})
		}
	}
	mutating, err := c.clients.Kubernetes.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "mutatingwebhookconfigurations.admissionregistration.k8s.io", err)
	} else {
		for index := range mutating.Items {
			configuration := &mutating.Items[index]
			details := []snapshot.KeyValue{{Key: "webhooks", Value: strconv.Itoa(len(configuration.Webhooks))}}
			for _, webhook := range configuration.Webhooks {
				if webhook.FailurePolicy != nil {
					details = append(details, snapshot.KeyValue{Key: "failurePolicy", Value: string(*webhook.FailurePolicy)})
				}
			}
			value.SecurityControls = append(value.SecurityControls, snapshot.SecurityControl{Ref: objectRef(admissionv1.GroupName, "MutatingWebhookConfiguration", configuration), ControlType: "MutatingWebhook", Details: details, SemanticsUnknown: true})
		}
	}
}

func (c *Collector) collectExternalPolicyMetadata(ctx context.Context, value *snapshot.Snapshot) {
	seen := make(map[schema.GroupVersionResource]struct{})
	for _, resource := range value.APIResources {
		if !isExternalPolicyResource(resource.APIGroup, resource.Name) {
			continue
		}
		gvr := schema.GroupVersionResource{Group: resource.APIGroup, Version: resource.Version, Resource: resource.Name}
		if _, ok := seen[gvr]; ok {
			continue
		}
		seen[gvr] = struct{}{}
		var items *metav1.PartialObjectMetadataList
		var err error
		if resource.Namespaced {
			items, err = c.clients.Metadata.Resource(gvr).Namespace(c.namespace()).List(ctx, metav1.ListOptions{})
		} else {
			items, err = c.clients.Metadata.Resource(gvr).List(ctx, metav1.ListOptions{})
		}
		if err != nil {
			c.warn(value, resource.Name+"."+resource.APIGroup, err)
			continue
		}
		for index := range items.Items {
			item := &items.Items[index]
			value.SecurityControls = append(value.SecurityControls, snapshot.SecurityControl{
				Ref: objectRef(resource.APIGroup, resource.Kind, item), ControlType: externalControlType(resource.APIGroup), Details: []snapshot.KeyValue{{Key: "resource", Value: resource.Name}}, SemanticsUnknown: true,
			})
		}
	}
}

func isExternalPolicyResource(group, resource string) bool {
	if group == "kyverno.io" {
		return resource == "policies" || resource == "clusterpolicies" || resource == "policyexceptions"
	}
	if group == "templates.gatekeeper.sh" {
		return resource == "constrainttemplates"
	}
	return group == "constraints.gatekeeper.sh"
}

func externalControlType(group string) string {
	if strings.Contains(group, "gatekeeper") {
		return "Gatekeeper"
	}
	return "Kyverno"
}

func labelValue(values map[string]string, key string) string {
	if values == nil {
		return ""
	}
	return values[key]
}
