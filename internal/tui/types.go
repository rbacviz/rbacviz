// Package tui presents immutable application results through a Bubble Tea UI.
package tui

import (
	"context"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/attackpath"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
	"github.com/rbacviz/rbacviz/internal/remediation"
	"github.com/rbacviz/rbacviz/internal/risk"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// SnapshotLoader obtains the canonical input without exposing collection to UI code.
type SnapshotLoader func(context.Context) (snapshot.Snapshot, error)

// Dataset is the immutable result bundle shared with every screen.
type Dataset struct {
	Snapshot    snapshot.Snapshot
	Graph       graphmodel.Stats
	Nodes       []graphmodel.Node
	Findings    analysis.Result
	Paths       attackpath.Result
	Risk        risk.Result
	Remediation remediation.Result
}

// Options configures one independent TUI program.
type Options struct {
	Context context.Context
	Load    SnapshotLoader
	KeyMap  KeyMap
	NoColor bool
}

type stage uint8

const (
	stageSnapshot stage = iota
	stageGraph
	stageFindings
	stagePaths
	stageRisk
	stageReady
)

func (value stage) String() string {
	switch value {
	case stageSnapshot:
		return "loading snapshot"
	case stageGraph:
		return "building permission graph"
	case stageFindings:
		return "evaluating findings"
	case stagePaths:
		return "ranking attack paths"
	case stageRisk:
		return "calculating risk"
	default:
		return "ready"
	}
}

// View identifies one implemented top-level screen.
type View uint8

const (
	// ViewOverview is the cluster summary screen.
	ViewOverview View = iota
	// ViewIdentities lists observed users and groups.
	ViewIdentities
	// ViewServiceAccounts lists namespaced workload identities.
	ViewServiceAccounts
	// ViewNamespaces lists observed namespace risk.
	ViewNamespaces
	// ViewRoles lists namespaced RBAC roles.
	ViewRoles
	// ViewClusterRoles lists cluster-scoped RBAC roles.
	ViewClusterRoles
	// ViewPermissions lists normalized effective capabilities.
	ViewPermissions
	// ViewFindings lists evidence-backed security findings.
	ViewFindings
	// ViewAttackPaths lists ranked privilege-escalation paths.
	ViewAttackPaths
	// ViewWarnings lists collection and analysis gaps.
	ViewWarnings
)

var views = []View{
	ViewOverview, ViewIdentities, ViewServiceAccounts, ViewNamespaces,
	ViewRoles, ViewClusterRoles, ViewPermissions, ViewFindings,
	ViewAttackPaths, ViewWarnings,
}

func (value View) String() string {
	switch value {
	case ViewOverview:
		return "Overview"
	case ViewIdentities:
		return "Identities"
	case ViewServiceAccounts:
		return "ServiceAccounts"
	case ViewNamespaces:
		return "Namespaces"
	case ViewRoles:
		return "Roles"
	case ViewClusterRoles:
		return "ClusterRoles"
	case ViewPermissions:
		return "Permissions"
	case ViewFindings:
		return "Findings"
	case ViewAttackPaths:
		return "Attack Paths"
	default:
		return "Warnings"
	}
}

type item struct {
	ID          string
	Title       string
	Subtitle    string
	Namespace   string
	Severity    string
	Confidence  string
	Search      string
	Detail      string
	Evidence    string
	Remediation string
	Risk        int
}

type modal uint8

const (
	modalNone modal = iota
	modalSearch
	modalHelp
	modalEvidence
	modalRemediation
)

type panel int

const (
	panelList panel = iota
	panelInspector
	panelEvidence
)

type snapshotLoadedMsg struct{ value snapshot.Snapshot }
type graphLoadedMsg struct {
	stats graphmodel.Stats
	nodes []graphmodel.Node
}
type findingsLoadedMsg struct{ value analysis.Result }
type pathsLoadedMsg struct{ value attackpath.Result }
type pathLoadErrorMsg struct{ err error }
type riskLoadedMsg struct{ value risk.Result }
type remediationLoadedMsg struct{ value remediation.Result }
type remediationLoadErrorMsg struct{ err error }
type loadErrorMsg struct{ err error }
