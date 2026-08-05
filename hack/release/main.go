// Command release builds deterministic multi-platform release artifacts.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rbacviz/rbacviz/internal/release"
)

func main() {
	var version, commit, epochValue, output, goBinary string
	flag.StringVar(&version, "version", "", "semantic release version, for example v0.1.0")
	flag.StringVar(&commit, "commit", "", "source commit identifier")
	flag.StringVar(&epochValue, "source-date-epoch", os.Getenv("SOURCE_DATE_EPOCH"), "reproducible Unix build timestamp")
	flag.StringVar(&output, "output", "dist/release", "empty release output directory")
	flag.StringVar(&goBinary, "go", "go", "Go toolchain executable")
	flag.Parse()
	epoch, err := release.ParseEpoch(epochValue)
	if err != nil {
		fatal(err)
	}
	repository, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	manifest, err := release.Build(context.Background(), release.Options{RepoDir: repository, OutputDir: filepath.Clean(output), Version: version, Commit: commit, Epoch: epoch, GoBinary: goBinary})
	if err != nil {
		fatal(err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(data))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "release:", err)
	os.Exit(1)
}
