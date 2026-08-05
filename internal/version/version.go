// Package version owns deterministic build metadata rendering.
package version

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strconv"
)

// Info is immutable build metadata injected into the CLI.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	Dirty     bool   `json:"dirty"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Current combines linker-injected values with runtime metadata.
func Current(buildVersion, commit, buildDate, dirty string) Info {
	isDirty, _ := strconv.ParseBool(dirty)
	return Info{
		Version: buildVersion, Commit: commit, BuildDate: buildDate, Dirty: isDirty,
		GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// Write renders build metadata in a stable human or JSON representation.
func Write(writer io.Writer, output string, info Info) error {
	switch output {
	case "human":
		dirty := ""
		if info.Dirty {
			dirty = " (dirty)"
		}
		_, err := fmt.Fprintf(writer, "rbacviz %s\ncommit: %s%s\nbuilt: %s\ngo: %s\nplatform: %s\n",
			info.Version, info.Commit, dirty, info.BuildDate, info.GoVersion, info.Platform)
		return err
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(info)
	default:
		return fmt.Errorf("unsupported version output %q", output)
	}
}
