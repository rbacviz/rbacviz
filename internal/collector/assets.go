package collector

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

type metadataAssetSpec struct {
	gvr        schema.GroupVersionResource
	apiGroup   string
	kind       string
	assetType  string
	namespaced bool
}

func (c *Collector) collectAssets(ctx context.Context, value *snapshot.Snapshot) {
	specs := []metadataAssetSpec{
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, kind: "Secret", assetType: "secret", namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, kind: "ConfigMap", assetType: "config-map", namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "nodes"}, kind: "Node", assetType: "node"},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumes"}, kind: "PersistentVolume", assetType: "persistent-volume"},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}, kind: "PersistentVolumeClaim", assetType: "persistent-volume-claim", namespaced: true},
		{gvr: schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests"}, apiGroup: "certificates.k8s.io", kind: "CertificateSigningRequest", assetType: "certificate-signing-request"},
		{gvr: schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}, apiGroup: "networking.k8s.io", kind: "Ingress", assetType: "ingress", namespaced: true},
		{gvr: schema.GroupVersionResource{Version: "v1", Resource: "services"}, kind: "Service", assetType: "service", namespaced: true},
	}
	for _, spec := range specs {
		c.collectMetadataAssets(ctx, value, spec)
	}
}

func (c *Collector) collectMetadataAssets(ctx context.Context, value *snapshot.Snapshot, spec metadataAssetSpec) {
	var items *metav1.PartialObjectMetadataList
	var err error
	if spec.namespaced {
		items, err = c.clients.Metadata.Resource(spec.gvr).Namespace(c.namespace()).List(ctx, metav1.ListOptions{})
	} else {
		items, err = c.clients.Metadata.Resource(spec.gvr).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		c.warn(value, spec.gvr.Resource+"."+spec.gvr.Group, err)
		return
	}
	for index := range items.Items {
		item := &items.Items[index]
		value.Assets = append(value.Assets, snapshot.Asset{
			Ref: objectRef(spec.apiGroup, spec.kind, item), Labels: labels(item.Labels), AssetType: spec.assetType,
		})
	}
}
