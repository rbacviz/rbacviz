package collector

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func (c *Collector) collectWorkloads(ctx context.Context, value *snapshot.Snapshot) {
	namespace := c.namespace()
	pods, err := c.clients.Kubernetes.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "pods", err)
	} else {
		for index := range pods.Items {
			pod := &pods.Items[index]
			value.Workloads = append(value.Workloads, workload(objectRef("", "Pod", pod), pod, pod.Spec))
		}
	}
	deployments, err := c.clients.Kubernetes.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "deployments.apps", err)
	} else {
		for index := range deployments.Items {
			value.Workloads = append(value.Workloads, deploymentWorkload(&deployments.Items[index]))
		}
	}
	daemonSets, err := c.clients.Kubernetes.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "daemonsets.apps", err)
	} else {
		for index := range daemonSets.Items {
			value.Workloads = append(value.Workloads, daemonSetWorkload(&daemonSets.Items[index]))
		}
	}
	statefulSets, err := c.clients.Kubernetes.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "statefulsets.apps", err)
	} else {
		for index := range statefulSets.Items {
			value.Workloads = append(value.Workloads, statefulSetWorkload(&statefulSets.Items[index]))
		}
	}
	jobs, err := c.clients.Kubernetes.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "jobs.batch", err)
	} else {
		for index := range jobs.Items {
			value.Workloads = append(value.Workloads, jobWorkload(&jobs.Items[index]))
		}
	}
	cronJobs, err := c.clients.Kubernetes.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "cronjobs.batch", err)
	} else {
		for index := range cronJobs.Items {
			value.Workloads = append(value.Workloads, cronJobWorkload(&cronJobs.Items[index]))
		}
	}
}
