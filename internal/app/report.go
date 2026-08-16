package app

import (
	"context"

	"github.com/rbacviz/rbacviz/internal/report"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

// GenerateReport runs the bounded, offline-safe report pipeline.
func GenerateReport(ctx context.Context, value snapshot.Snapshot, options report.Options) (report.Result, error) {
	return report.Build(ctx, value, options)
}
