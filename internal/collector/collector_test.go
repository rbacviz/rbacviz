package collector_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/rbacviz/rbacviz/internal/collector"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type discoveryStub struct {
	*discoveryfake.FakeDiscovery
	resources []*metav1.APIResourceList
}

func (d *discoveryStub) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return d.resources, nil
}

func TestCollectorBuildsCredentialFreeCanonicalSnapshot(t *testing.T) {
	t.Parallel()
	privileged := true
	serviceToken := false
	failurePolicy := admissionv1.Fail
	kube := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "prod"}, AutomountServiceAccountToken: &serviceToken},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "prod"}, Data: map[string][]byte{"password": []byte("supersecret")}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "prod"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "readers", Namespace: "prod"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "reader"}, Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}, {Kind: rbacv1.ServiceAccountKind, Name: "deployer"}}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "deployer", Containers: []corev1.Container{{Name: "api", Image: "example/api:v1", Env: []corev1.EnvVar{{Name: "PASSWORD", Value: "plaintext-credential"}}, SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}, Volumes: []corev1.Volume{{Name: "database", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "database"}}}}}}}},
		&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "policy.example"}, Webhooks: []admissionv1.ValidatingWebhook{{Name: "policy.example", FailurePolicy: &failurePolicy}}},
	)

	metadataClient := metadatafake.NewSimpleMetadataClient(metadatafake.NewTestScheme())
	metadataClient.PrependReactor("list", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
		list := &metav1.List{}
		if action.GetResource().Resource == "secrets" {
			list.Items = append(list.Items, runtime.RawExtension{Object: &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "prod", Labels: map[string]string{"owner": "platform"}}}})
		}
		return true, list, nil
	})
	discovery := &discoveryStub{FakeDiscovery: &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{}}, resources: []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}}}}
	live, err := collector.New(collector.Clients{Kubernetes: kube, Discovery: discovery, Metadata: metadataClient}, collector.Options{Namespace: "prod", Context: "test", ToolVersion: "v0.2.0", Now: func() time.Time { return time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	value, err := live.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !value.Metadata.Complete || len(value.Warnings) != 0 {
		t.Fatalf("complete = %t, warnings = %v", value.Metadata.Complete, value.Warnings)
	}
	if len(value.Roles) != 1 || len(value.Bindings) != 1 || len(value.ServiceAccounts) != 1 {
		t.Fatalf("unexpected RBAC inventory: roles=%d bindings=%d serviceAccounts=%d", len(value.Roles), len(value.Bindings), len(value.ServiceAccounts))
	}
	if len(value.Identities) != 2 {
		t.Fatalf("identities = %d, want 2", len(value.Identities))
	}
	if len(value.Workloads) != 1 || value.Workloads[0].ServiceAccountName != "deployer" || len(value.Workloads[0].Volumes) != 1 {
		t.Fatalf("unexpected workloads: %#v", value.Workloads)
	}
	if len(value.Assets) != 1 || value.Assets[0].Ref.Kind != "Secret" {
		t.Fatalf("unexpected assets: %#v", value.Assets)
	}
	if len(value.SecurityControls) != 2 {
		t.Fatalf("security controls = %d, want PSA and webhook", len(value.SecurityControls))
	}
	data, err := snapshot.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"supersecret", "plaintext-credential", `\"data\"`, `\"stringData\"`, "caBundle"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("snapshot leaked %q: %s", forbidden, data)
		}
	}
}

func TestCollectorRecordsSafePartialWarnings(t *testing.T) {
	t.Parallel()
	kube := fake.NewSimpleClientset()
	kube.PrependReactor("list", "roles", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: rbacv1.GroupName, Resource: "roles"}, "", errors.New("server https://private.example rejected bearer token abc"))
	})
	metadataClient := metadatafake.NewSimpleMetadataClient(metadatafake.NewTestScheme())
	metadataClient.PrependReactor("list", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, &metav1.List{}, nil
	})
	discovery := &discoveryStub{FakeDiscovery: &discoveryfake.FakeDiscovery{Fake: &clienttesting.Fake{}}}
	live, err := collector.New(collector.Clients{Kubernetes: kube, Discovery: discovery, Metadata: metadataClient}, collector.Options{Now: func() time.Time { return time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	value, err := live.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if value.Metadata.Complete || len(value.Warnings) != 1 {
		t.Fatalf("complete = %t, warnings = %#v", value.Metadata.Complete, value.Warnings)
	}
	warning := value.Warnings[0]
	if warning.Code != "Forbidden" || strings.Contains(warning.Message, "private.example") || strings.Contains(warning.Message, "abc") {
		t.Fatalf("unsafe warning = %#v", warning)
	}
}
