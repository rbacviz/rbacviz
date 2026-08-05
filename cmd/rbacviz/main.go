// Package main is the rbacviz process entry point.
package main

import (
	"context"
	"os"

	"github.com/rbacviz/rbacviz/internal/cli"
	"github.com/rbacviz/rbacviz/internal/version"
)

var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
	buildDirty   = "false"
)

func main() {
	info := version.Current(buildVersion, buildCommit, buildDate, buildDirty)
	code := cli.Execute(context.Background(), os.Args[1:], cli.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}, cli.Dependencies{
		Version:       info,
		LookupEnv:     os.LookupEnv,
		UserConfigDir: os.UserConfigDir,
	})
	os.Exit(code)
}
