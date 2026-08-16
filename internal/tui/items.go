package tui

import (
	"fmt"
	"sort"
	"strings"

	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func buildItems(data Dataset) map[View][]item {
	result := make(map[View][]item, len(views))
	result[ViewOverview] = overviewItems(data)
	result[ViewIdentities] = identityItems(data)
	result[ViewServiceAccounts] = serviceAccountItems(data)
	result[ViewNamespaces] = namespaceItems(data)
	result[ViewRoles], result[ViewClusterRoles] = roleItems(data)
	result[ViewPermissions] = permissionItems(data)
	result[ViewFindings] = findingItems(data)
	result[ViewAttackPaths] = pathItems(data)
	result[ViewWarnings] = warningItems(data)
	return result
}

func overviewItems(data Dataset) []item {
	posture := activeRisk(data)
	cluster := posture.Cluster
	pathsComplete := data.Paths.SchemaVersion == "" || data.Paths.Complete
	complete := data.Snapshot.Metadata.Complete && data.Findings.Complete && pathsComplete && posture.Complete
	return []item{
		{ID: "overview:risk", Title: fmt.Sprintf("Risk Index  %d/100", cluster.Score), Subtitle: string(cluster.Severity), Severity: string(cluster.Severity), Risk: cluster.Score, Detail: lines(
			"CLUSTER RISK INDEX", fmt.Sprintf("Index: %d/100 (%s)", cluster.Score, cluster.Severity),
			"Posture indicator; not breach probability.", cluster.Explanation,
			fmt.Sprintf("Root-cause families: %d", cluster.RiskFamilyCount),
			fmt.Sprintf("Contributing families: %d", cluster.ContributingFamilies),
			fmt.Sprintf("Accepted exceptions: %d", len(data.Suppressions.Accepted)),
			fmt.Sprintf("Distinct semantic units: %d", cluster.DistinctRiskUnits), fmt.Sprintf("Attack paths: %d", cluster.PathCount)),
			Evidence: strings.Join(cluster.PathIDs, "\n")},
		{ID: "overview:paths", Title: fmt.Sprintf("Attack paths  %d", pathSummaryCount(data)), Subtitle: pathSummarySubtitle(data), Detail: pathSummaryDetail(data)},
		{ID: "overview:findings", Title: fmt.Sprintf("Findings  %d", len(data.Findings.Findings)), Subtitle: severityCounts(data), Detail: lines(
			"SECURITY FINDINGS", fmt.Sprintf("Ruleset: %s", data.Findings.RulesetVersion), severityCounts(data), fmt.Sprintf("Warnings: %d", len(data.Findings.Warnings)))},
		{ID: "overview:graph", Title: fmt.Sprintf("Permission graph  %d nodes", data.Graph.Nodes), Subtitle: fmt.Sprintf("%d edges", data.Graph.Edges), Detail: lines(
			"PERMISSION GRAPH", fmt.Sprintf("Nodes: %d", data.Graph.Nodes), fmt.Sprintf("Edges: %d", data.Graph.Edges), fmt.Sprintf("Warnings: %d", data.Graph.Warnings))},
		{ID: "overview:inventory", Title: fmt.Sprintf("Identities  %d", len(data.Snapshot.Identities)), Subtitle: fmt.Sprintf("%d roles · %d bindings", len(data.Snapshot.Roles), len(data.Snapshot.Bindings)), Detail: inventoryDetail(data.Snapshot)},
		{ID: "overview:collection", Title: completionTitle(complete), Subtitle: fmt.Sprintf("%d collection warnings", len(data.Snapshot.Warnings)), Severity: completionSeverity(complete), Detail: collectionDetail(data.Snapshot)},
	}
}

func pathSummaryCount(data Dataset) int {
	if data.Paths.SchemaVersion != "" {
		return len(data.Paths.Paths)
	}
	return len(data.Risk.PathScores)
}

func pathSummarySubtitle(data Dataset) string {
	if data.Paths.SchemaVersion == "" {
		return fmt.Sprintf("%d scored summaries · details on demand", len(data.Risk.PathScores))
	}
	return fmt.Sprintf("expanded %d · truncated %t", data.Paths.Expanded, data.Paths.Truncated)
}

func pathSummaryDetail(data Dataset) string {
	parts := []string{"ATTACK PATH ANALYSIS", fmt.Sprintf("Scored path summaries: %d", len(data.Risk.PathScores))}
	if data.Paths.SchemaVersion == "" {
		parts = append(parts, "Detailed evidence has not been materialized.", "Open Attack Paths to run the bounded, cancellable detail query.")
	} else {
		parts = append(parts, fmt.Sprintf("Detailed paths: %d", len(data.Paths.Paths)), fmt.Sprintf("Expanded candidates: %d", data.Paths.Expanded), fmt.Sprintf("Truncated: %t", data.Paths.Truncated))
	}
	return strings.Join(parts, "\n")
}

func identityItems(data Dataset) []item {
	risks := identityRisk(data)
	values := make([]item, 0, len(data.Snapshot.Identities))
	for _, identity := range data.Snapshot.Identities {
		if identity.Kind == snapshot.IdentityServiceAccount {
			continue
		}
		value := permission.Identity{Kind: identity.Kind, Namespace: identity.Namespace, Name: identity.Name}
		riskValue := risks[value.String()]
		title := value.String()
		values = append(values, item{
			ID: identity.ID, Title: title, Subtitle: fmt.Sprintf("%s · risk %d %s", identity.Kind, riskValue.Score, riskValue.Severity),
			Namespace: identity.Namespace, Severity: string(riskValue.Severity), Risk: riskValue.Score,
			Search: strings.ToLower(title + " " + string(identity.Kind)),
			Detail: lines("IDENTITY", title, fmt.Sprintf("Kind: %s", identity.Kind), fmt.Sprintf("Risk Index: %d/100 %s", riskValue.Score, riskValue.Severity),
				fmt.Sprintf("Paths: %d", riskValue.Paths), fmt.Sprintf("Root-cause families: %d", riskValue.Families),
				fmt.Sprintf("Distinct semantic units: %d", riskValue.Units), riskValue.Explanation),
			Evidence: strings.Join(riskValue.IDs, "\n"),
		})
	}
	return values
}

func serviceAccountItems(data Dataset) []item {
	risks := identityRisk(data)
	values := make([]item, 0, len(data.Snapshot.ServiceAccounts))
	for _, account := range data.Snapshot.ServiceAccounts {
		identity := permission.Identity{Kind: snapshot.IdentityServiceAccount, Namespace: account.Ref.Namespace, Name: account.Ref.Name}
		riskValue := risks[identity.String()]
		automount := "inherited"
		if account.AutomountServiceToken != nil {
			automount = fmt.Sprintf("%t", *account.AutomountServiceToken)
		}
		values = append(values, item{
			ID: account.ID, Title: identity.String(), Namespace: account.Ref.Namespace, Risk: riskValue.Score,
			Severity: string(riskValue.Severity), Subtitle: fmt.Sprintf("risk %d %s · automount %s", riskValue.Score, riskValue.Severity, automount),
			Detail: lines("SERVICE ACCOUNT", identity.String(), fmt.Sprintf("Namespace: %s", account.Ref.Namespace),
				fmt.Sprintf("Automount token: %s", automount), fmt.Sprintf("Risk Index: %d/100 %s", riskValue.Score, riskValue.Severity),
				fmt.Sprintf("Root-cause families: %d", riskValue.Families), riskValue.Explanation),
			Evidence: strings.Join(riskValue.IDs, "\n"),
		})
	}
	return values
}

func namespaceItems(data Dataset) []item {
	posture := activeRisk(data)
	names := observedNamespaces(data.Snapshot)
	risks := make(map[string]riskSummary, len(posture.Namespaces))
	for _, value := range posture.Namespaces {
		risks[value.Namespace] = riskSummary{Score: value.Score, Severity: string(value.Severity), Paths: value.PathCount, Units: value.DistinctRiskUnits, Families: value.RiskFamilyCount, Explanation: value.Explanation, IDs: value.PathIDs}
	}
	values := make([]item, 0, len(names))
	for _, name := range names {
		riskValue := risks[name]
		counts := namespaceCounts(data.Snapshot, name)
		values = append(values, item{
			ID: "namespace:" + name, Title: name, Namespace: name, Risk: riskValue.Score, Severity: riskValue.Severity,
			Subtitle: fmt.Sprintf("risk %d %s · %d workloads", riskValue.Score, defaultText(riskValue.Severity, "INFO"), counts.workloads),
			Detail: lines("NAMESPACE", name, fmt.Sprintf("Risk Index: %d/100 %s", riskValue.Score, defaultText(riskValue.Severity, "INFO")),
				fmt.Sprintf("Root-cause families: %d", riskValue.Families), fmt.Sprintf("Roles: %d", counts.roles), fmt.Sprintf("Bindings: %d", counts.bindings),
				fmt.Sprintf("Workloads: %d", counts.workloads), fmt.Sprintf("Assets: %d", counts.assets), riskValue.Explanation),
			Evidence: strings.Join(riskValue.IDs, "\n"),
		})
	}
	return values
}

func roleItems(data Dataset) ([]item, []item) {
	var roles, clusterRoles []item
	for _, role := range data.Snapshot.Roles {
		wildcard := roleHasWildcard(role)
		value := item{ID: role.ID, Title: qualified(role.Ref), Namespace: role.Ref.Namespace,
			Subtitle: fmt.Sprintf("%d rules · wildcard %t", len(role.Rules), wildcard),
			Detail:   roleDetail(role), Evidence: roleEvidence(role)}
		value.Search = strings.ToLower(value.Title + " " + value.Subtitle)
		if role.Ref.Kind == "ClusterRole" {
			clusterRoles = append(clusterRoles, value)
		} else {
			roles = append(roles, value)
		}
	}
	return roles, clusterRoles
}

func permissionItems(data Dataset) []item {
	values := make([]item, 0)
	for _, node := range data.Nodes {
		if node.Type != graphmodel.NodeCapability || node.Capability == nil {
			continue
		}
		capability := node.Capability
		title := capabilityTitle(*capability)
		explanations := data.Explanations.Lookup(node.ID)
		grantCount := explanationGrantCount(explanations, *capability)
		evidence := capabilityEvidence(*capability)
		if grantCount > 0 {
			evidence = explanationEvidence(explanations, *capability)
		}
		values = append(values, item{ID: node.ID, Title: title, Namespace: capability.Namespace,
			Subtitle: fmt.Sprintf("%s · %d independent grants", capability.Scope, grantCount),
			Detail:   capabilityDetailWithGrantCount(*capability, grantCount), Evidence: evidence,
			Search: strings.ToLower(title + " " + string(capability.Scope) + " " + capability.Namespace)})
	}
	return values
}

type riskSummary struct {
	Score        int
	Severity     string
	Paths, Units int
	Families     int
	Explanation  string
	IDs          []string
}

func identityRisk(data Dataset) map[string]riskSummary {
	posture := activeRisk(data)
	result := make(map[string]riskSummary, len(posture.Identities))
	for _, value := range posture.Identities {
		result[value.Key] = riskSummary{Score: value.Score, Severity: string(value.Severity), Paths: value.PathCount, Units: value.DistinctRiskUnits, Families: value.RiskFamilyCount, Explanation: value.Explanation, IDs: value.PathIDs}
	}
	return result
}

func activeRisk(data Dataset) risk.Result {
	if data.ActiveRisk.SchemaVersion != "" {
		return data.ActiveRisk
	}
	return data.Risk
}

type objectCounts struct{ roles, bindings, workloads, assets int }

func namespaceCounts(value snapshot.Snapshot, namespace string) objectCounts {
	var result objectCounts
	for _, item := range value.Roles {
		if item.Ref.Namespace == namespace {
			result.roles++
		}
	}
	for _, item := range value.Bindings {
		if item.Ref.Namespace == namespace {
			result.bindings++
		}
	}
	for _, item := range value.Workloads {
		if item.Ref.Namespace == namespace {
			result.workloads++
		}
	}
	for _, item := range value.Assets {
		if item.Ref.Namespace == namespace {
			result.assets++
		}
	}
	return result
}

func observedNamespaces(value snapshot.Snapshot) []string {
	set := make(map[string]struct{})
	add := func(namespace string) {
		if namespace != "" {
			set[namespace] = struct{}{}
		}
	}
	add(value.Metadata.Namespace)
	for _, item := range value.Identities {
		add(item.Namespace)
	}
	for _, item := range value.Roles {
		add(item.Ref.Namespace)
	}
	for _, item := range value.Bindings {
		add(item.Ref.Namespace)
	}
	for _, item := range value.ServiceAccounts {
		add(item.Ref.Namespace)
	}
	for _, item := range value.Workloads {
		add(item.Ref.Namespace)
	}
	for _, item := range value.Assets {
		add(item.Ref.Namespace)
	}
	values := make([]string, 0, len(set))
	for name := range set {
		values = append(values, name)
	}
	sort.Strings(values)
	return values
}
