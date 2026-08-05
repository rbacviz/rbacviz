package collector

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func (c *Collector) collectRBAC(ctx context.Context, value *snapshot.Snapshot) {
	roles, err := c.clients.Kubernetes.RbacV1().Roles(c.namespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "roles.rbac.authorization.k8s.io", err)
	} else {
		for index := range roles.Items {
			role := &roles.Items[index]
			value.Roles = append(value.Roles, snapshot.Role{
				Ref: objectRef(rbacv1.GroupName, "Role", role), Labels: labels(role.Labels), Rules: policyRules(role.Rules),
			})
		}
	}

	clusterRoles, err := c.clients.Kubernetes.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "clusterroles.rbac.authorization.k8s.io", err)
	} else {
		for index := range clusterRoles.Items {
			role := &clusterRoles.Items[index]
			value.Roles = append(value.Roles, snapshot.Role{
				Ref: objectRef(rbacv1.GroupName, "ClusterRole", role), Labels: labels(role.Labels), Rules: policyRules(role.Rules),
				AggregationSelectors: aggregationSelectors(role.AggregationRule),
			})
		}
	}

	roleBindings, err := c.clients.Kubernetes.RbacV1().RoleBindings(c.namespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "rolebindings.rbac.authorization.k8s.io", err)
	} else {
		for index := range roleBindings.Items {
			binding := &roleBindings.Items[index]
			value.Bindings = append(value.Bindings, snapshot.Binding{
				Ref: objectRef(rbacv1.GroupName, "RoleBinding", binding), Labels: labels(binding.Labels),
				RoleRef: roleRef(binding.RoleRef, binding.Namespace), Subjects: subjects(binding.Subjects, binding.Namespace),
			})
		}
	}

	clusterBindings, err := c.clients.Kubernetes.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "clusterrolebindings.rbac.authorization.k8s.io", err)
	} else {
		for index := range clusterBindings.Items {
			binding := &clusterBindings.Items[index]
			value.Bindings = append(value.Bindings, snapshot.Binding{
				Ref: objectRef(rbacv1.GroupName, "ClusterRoleBinding", binding), Labels: labels(binding.Labels),
				RoleRef: roleRef(binding.RoleRef, ""), Subjects: subjects(binding.Subjects, ""),
			})
		}
	}
}

func roleRef(value rbacv1.RoleRef, bindingNamespace string) snapshot.ObjectRef {
	namespace := ""
	if value.Kind == "Role" {
		namespace = bindingNamespace
	}
	return snapshot.ObjectRef{APIGroup: value.APIGroup, Kind: value.Kind, Namespace: namespace, Name: value.Name}
}

func (c *Collector) collectServiceAccounts(ctx context.Context, value *snapshot.Snapshot) {
	accounts, err := c.clients.Kubernetes.CoreV1().ServiceAccounts(c.namespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		c.warn(value, "serviceaccounts", err)
		return
	}
	for index := range accounts.Items {
		account := &accounts.Items[index]
		value.ServiceAccounts = append(value.ServiceAccounts, snapshot.ServiceAccount{
			Ref: objectRef("", "ServiceAccount", account), Labels: labels(account.Labels), AutomountServiceToken: account.AutomountServiceAccountToken,
		})
	}
}
