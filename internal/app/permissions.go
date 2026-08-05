package app

import (
	"fmt"

	"github.com/rbacviz/rbacviz/internal/permission"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// PermissionAnalyzer is the application query surface shared by CLI and the
// future TUI. All methods are deterministic for the snapshot supplied at
// construction time.
type PermissionAnalyzer struct {
	resolver *permission.Resolver
}

// NewPermissionAnalyzer initializes permission queries over one immutable
// snapshot.
func NewPermissionAnalyzer(value snapshot.Snapshot) (*PermissionAnalyzer, error) {
	resolver, err := permission.New(value)
	if err != nil {
		return nil, fmt.Errorf("initialize permission resolver: %w", err)
	}
	return &PermissionAnalyzer{resolver: resolver}, nil
}

// Permissions returns every effective capability for an identity.
func (analyzer *PermissionAnalyzer) Permissions(identity permission.Identity, groups []string) permission.Result {
	return analyzer.resolver.Permissions(identity, groups)
}

// WhoCan returns every directly represented subject matching an action.
func (analyzer *PermissionAnalyzer) WhoCan(action permission.Action) permission.WhoCanResult {
	return analyzer.resolver.WhoCan(action)
}

// WhyCan returns every grant explaining an identity/action match.
func (analyzer *PermissionAnalyzer) WhyCan(identity permission.Identity, groups []string, action permission.Action) permission.WhyCanResult {
	return analyzer.resolver.WhyCan(identity, groups, action)
}
