// Package collector adapts Kubernetes APIs into credential-free snapshots.
package collector

import (
	"fmt"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientOptions selects an out-of-cluster or default kubeconfig context.
type ClientOptions struct {
	Kubeconfig string
	Context    string
	Timeout    time.Duration
}

// Clients groups the narrow Kubernetes clients required by collection.
type Clients struct {
	Kubernetes       kubernetes.Interface
	Discovery        discovery.DiscoveryInterface
	Metadata         metadata.Interface
	DefaultNamespace string
}

// NewClients loads kubeconfig without ever exposing its credential fields.
func NewClients(options ClientOptions) (Clients, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if options.Kubeconfig != "" {
		rules.ExplicitPath = options.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: options.Context}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	defaultNamespace, _, err := clientConfig.Namespace()
	if err != nil {
		return Clients{}, fmt.Errorf("resolve kubeconfig namespace: %w", err)
	}
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return Clients{}, fmt.Errorf("load Kubernetes client configuration: %w", err)
	}
	restConfig = rest.CopyConfig(restConfig)
	restConfig.UserAgent = "rbacviz"
	if options.Timeout > 0 {
		restConfig.Timeout = options.Timeout
	}

	kubernetesClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return Clients{}, fmt.Errorf("create Kubernetes client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return Clients{}, fmt.Errorf("create discovery client: %w", err)
	}
	metadataClient, err := metadata.NewForConfig(restConfig)
	if err != nil {
		return Clients{}, fmt.Errorf("create metadata client: %w", err)
	}
	return Clients{Kubernetes: kubernetesClient, Discovery: discoveryClient, Metadata: metadataClient, DefaultNamespace: defaultNamespace}, nil
}
