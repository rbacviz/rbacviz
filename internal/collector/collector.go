package collector

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// Options controls collection scope and snapshot provenance.
type Options struct {
	Namespace     string
	AllNamespaces bool
	Context       string
	ToolVersion   string
	Now           func() time.Time
}

// Collector reads cluster metadata into a normalized snapshot.
type Collector struct {
	clients Clients
	options Options
}

// New constructs a collector from injectable interfaces.
func New(clients Clients, options Options) (*Collector, error) {
	if clients.Kubernetes == nil || clients.Discovery == nil || clients.Metadata == nil {
		return nil, fmt.Errorf("collector requires Kubernetes, discovery, and metadata clients")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Collector{clients: clients, options: options}, nil
}

// Collect attempts every independent API group and records safe partial warnings.
func (c *Collector) Collect(ctx context.Context) (snapshot.Snapshot, error) {
	value := snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion,
		ToolVersion:   c.options.ToolVersion,
		Metadata: snapshot.Metadata{
			CollectedAt:   c.options.Now().UTC().Format(time.RFC3339Nano),
			Context:       c.options.Context,
			Namespace:     c.options.Namespace,
			AllNamespaces: c.options.AllNamespaces,
			Complete:      true,
		},
	}

	c.collectDiscovery(ctx, &value)
	c.collectRBAC(ctx, &value)
	c.collectServiceAccounts(ctx, &value)
	c.collectWorkloads(ctx, &value)
	c.collectAssets(ctx, &value)
	c.collectSecurityControls(ctx, &value)

	canonical, err := snapshot.Canonicalize(value)
	if err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("canonicalize collected snapshot: %w", err)
	}
	return canonical, nil
}

func (c *Collector) namespace() string {
	if c.options.AllNamespaces || c.options.Namespace == "" {
		return metav1.NamespaceAll
	}
	return c.options.Namespace
}

func (c *Collector) warn(value *snapshot.Snapshot, resource string, err error) {
	if err == nil {
		return
	}
	reason := apierrors.ReasonForError(err)
	code := string(reason)
	if code == "" || code == string(metav1.StatusReasonUnknown) {
		code = "RequestFailed"
	}
	value.Warnings = append(value.Warnings, snapshot.Warning{
		Resource: resource,
		Code:     code,
		Message:  fmt.Sprintf("%s collection failed (%s)", resource, code),
	})
	value.Metadata.Complete = false
}

func (c *Collector) collectDiscovery(_ context.Context, value *snapshot.Snapshot) {
	resourceLists, err := c.clients.Discovery.ServerPreferredResources()
	if err != nil {
		c.warn(value, "api-discovery", err)
	}
	for _, list := range resourceLists {
		groupVersion, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			c.warn(value, "api-discovery/"+list.GroupVersion, parseErr)
			continue
		}
		for _, resource := range list.APIResources {
			if resource.Name == "" || resource.Kind == "" {
				continue
			}
			value.APIResources = append(value.APIResources, snapshot.APIResource{
				GroupVersion: list.GroupVersion,
				APIGroup:     groupVersion.Group,
				Version:      groupVersion.Version,
				Name:         resource.Name,
				Kind:         resource.Kind,
				Namespaced:   resource.Namespaced,
				Verbs:        append([]string(nil), resource.Verbs...),
			})
		}
	}
}
