// Package app orchestrates application use cases across adapters.
package app

import (
	"context"

	"github.com/rbacviz/rbacviz/internal/apperr"
	"github.com/rbacviz/rbacviz/internal/collector"
	"github.com/rbacviz/rbacviz/internal/config"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// CollectLiveSnapshot creates clients and collects one immutable cluster snapshot.
func CollectLiveSnapshot(ctx context.Context, cfg config.Config, toolVersion string) (snapshot.Snapshot, error) {
	clients, err := collector.NewClients(collector.ClientOptions{Kubeconfig: cfg.Kubeconfig, Context: cfg.Context, Timeout: cfg.Timeout})
	if err != nil {
		return snapshot.Snapshot{}, apperr.New(apperr.KindOperational, "app.snapshot.clients", "cannot initialize Kubernetes client", err)
	}
	namespace := cfg.Namespace
	if namespace == "" && !cfg.AllNamespaces {
		namespace = clients.DefaultNamespace
	}
	liveCollector, err := collector.New(clients, collector.Options{
		Namespace: namespace, AllNamespaces: cfg.AllNamespaces, Context: cfg.Context, ToolVersion: toolVersion,
	})
	if err != nil {
		return snapshot.Snapshot{}, apperr.New(apperr.KindOperational, "app.snapshot.collector", "cannot initialize Kubernetes collector", err)
	}
	value, err := liveCollector.Collect(ctx)
	if err != nil {
		return snapshot.Snapshot{}, apperr.New(apperr.KindOperational, "app.snapshot.collect", "cannot collect Kubernetes snapshot", err)
	}
	return value, nil
}
