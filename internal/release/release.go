package release

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

// Target is one supported release platform.
type Target struct {
	OS   string
	Arch string
}

// Options controls a complete deterministic release build.
type Options struct {
	RepoDir   string
	OutputDir string
	Version   string
	Commit    string
	Epoch     time.Time
	GoBinary  string
}

// Manifest records exactly what a release invocation produced.
type Manifest struct {
	SchemaVersion string   `json:"schemaVersion"`
	Version       string   `json:"version"`
	Commit        string   `json:"commit"`
	SourceDate    string   `json:"sourceDate"`
	GoVersion     string   `json:"goVersion"`
	Artifacts     []Digest `json:"artifacts"`
}

// Targets is the supported release matrix.
var Targets = []Target{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}, {OS: "darwin", Arch: "amd64"}, {OS: "darwin", Arch: "arm64"}, {OS: "windows", Arch: "amd64"}}

// Build compiles, packages, inventories, and checksums one release.
func Build(ctx context.Context, options Options) (Manifest, error) {
	if err := validateOptions(&options); err != nil {
		return Manifest{}, err
	}
	if err := requireEmptyOutput(options.OutputDir); err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(options.OutputDir, 0o750); err != nil {
		return Manifest{}, err
	}
	goVersion, err := commandOutput(ctx, options.RepoDir, nil, options.GoBinary, "version")
	if err != nil {
		return Manifest{}, err
	}
	versionName := strings.TrimPrefix(options.Version, "v")
	buildDir, err := os.MkdirTemp(options.OutputDir, ".build-*")
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = os.RemoveAll(buildDir) }()

	digests := make([]Digest, 0, len(Targets)+1)
	for _, target := range Targets {
		extension := ""
		if target.OS == "windows" {
			extension = ".exe"
		}
		binary := filepath.Join(buildDir, "rbacviz_"+target.OS+"_"+target.Arch+extension)
		if err := buildBinary(ctx, options, target, binary); err != nil {
			return Manifest{}, err
		}
		base := fmt.Sprintf("rbacviz_%s_%s_%s", versionName, target.OS, target.Arch)
		root := fmt.Sprintf("rbacviz_%s_%s_%s", versionName, target.OS, target.Arch)
		files := []File{{Name: "rbacviz" + extension, Path: binary, Mode: 0o755}}
		for _, name := range []string{"LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md"} {
			files = append(files, File{Name: name, Path: filepath.Join(options.RepoDir, name), Mode: 0o644})
		}
		archive := filepath.Join(options.OutputDir, base+".tar.gz")
		if target.OS == "windows" {
			archive = filepath.Join(options.OutputDir, base+".zip")
			err = Zip(archive, root, options.Epoch, files)
		} else {
			err = TarGz(archive, root, options.Epoch, files)
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("package %s/%s: %w", target.OS, target.Arch, err)
		}
		digest, err := FileDigest(archive)
		if err != nil {
			return Manifest{}, err
		}
		digests = append(digests, digest)
	}

	modules, err := listModules(ctx, options)
	if err != nil {
		return Manifest{}, err
	}
	sbom, err := CycloneDX("github.com/rbacviz/rbacviz", options.Version, options.Epoch.UTC().Format(time.RFC3339), modules)
	if err != nil {
		return Manifest{}, err
	}
	sbomPath := filepath.Join(options.OutputDir, fmt.Sprintf("rbacviz_%s_sbom.cdx.json", versionName))
	if err := writeAtomically(sbomPath, func(writer io.Writer) error {
		_, writeErr := writer.Write(sbom)
		return writeErr
	}); err != nil {
		return Manifest{}, err
	}
	sbomDigest, err := FileDigest(sbomPath)
	if err != nil {
		return Manifest{}, err
	}
	digests = append(digests, sbomDigest)
	sort.Slice(digests, func(i, j int) bool { return digests[i].Name < digests[j].Name })

	manifest := Manifest{SchemaVersion: "1.0", Version: options.Version, Commit: options.Commit, SourceDate: options.Epoch.UTC().Format(time.RFC3339), GoVersion: strings.TrimSpace(goVersion), Artifacts: digests}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	manifestPath := filepath.Join(options.OutputDir, fmt.Sprintf("rbacviz_%s_release-manifest.json", versionName))
	if err := writeAtomically(manifestPath, func(writer io.Writer) error {
		_, writeErr := writer.Write(append(manifestData, '\n'))
		return writeErr
	}); err != nil {
		return Manifest{}, err
	}
	manifestDigest, err := FileDigest(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	checksumInputs := append(append([]Digest(nil), digests...), manifestDigest)
	if err := WriteChecksums(filepath.Join(options.OutputDir, "checksums.txt"), checksumInputs); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func requireEmptyOutput(path string) error {
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect release output: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("release output %q is not empty", path)
	}
	return nil
}

func validateOptions(options *Options) error {
	if !versionPattern.MatchString(options.Version) {
		return fmt.Errorf("version %q is not semantic", options.Version)
	}
	if options.Commit == "" {
		return fmt.Errorf("commit is required")
	}
	if options.Epoch.IsZero() {
		return fmt.Errorf("source date epoch is required")
	}
	if options.GoBinary == "" {
		options.GoBinary = "go"
	}
	for _, name := range []string{"LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md", "go.mod", "go.sum"} {
		if _, err := os.Stat(filepath.Join(options.RepoDir, name)); err != nil {
			return fmt.Errorf("release input %s: %w", name, err)
		}
	}
	return nil
}

func buildBinary(ctx context.Context, options Options, target Target, output string) error {
	buildDate := options.Epoch.UTC().Format(time.RFC3339)
	ldflags := strings.Join([]string{"-s", "-w", "-buildid=", "-X", "main.buildVersion=" + options.Version, "-X", "main.buildCommit=" + options.Commit, "-X", "main.buildDate=" + buildDate, "-X", "main.buildDirty=false"}, " ")
	environment := []string{"CGO_ENABLED=0", "GOOS=" + target.OS, "GOARCH=" + target.Arch}
	_, err := commandOutput(ctx, options.RepoDir, environment, options.GoBinary, "build", "-buildvcs=false", "-trimpath", "-ldflags", ldflags, "-o", output, "./cmd/rbacviz")
	if err != nil {
		return fmt.Errorf("build %s/%s: %w", target.OS, target.Arch, err)
	}
	return nil
}

func listModules(ctx context.Context, options Options) ([]Module, error) {
	data, err := commandOutput(ctx, options.RepoDir, nil, options.GoBinary, "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(data))
	result := make([]Module, 0)
	for decoder.More() {
		var module Module
		if err := decoder.Decode(&module); err != nil {
			return nil, fmt.Errorf("decode module inventory: %w", err)
		}
		result = append(result, module)
	}
	return result, nil
}

func commandOutput(ctx context.Context, directory string, extraEnvironment []string, name string, arguments ...string) (string, error) {
	// #nosec G204 -- the local release operator explicitly selects the Go executable.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), extraEnvironment...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(arguments, " "), message)
	}
	return stdout.String(), nil
}

// ParseEpoch validates a SOURCE_DATE_EPOCH value.
func ParseEpoch(value string) (time.Time, error) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, fmt.Errorf("invalid SOURCE_DATE_EPOCH %q", value)
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// RuntimeGoBinary returns the current go executable name for callers and tests.
func RuntimeGoBinary() string {
	if runtime.GOOS == "windows" {
		return "go.exe"
	}
	return "go"
}

// ReadChecksums parses the strict checksum file emitted by WriteChecksums.
func ReadChecksums(data []byte) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 || parts[1] == "" {
			return nil, fmt.Errorf("invalid checksum line %q", scanner.Text())
		}
		result[parts[1]] = parts[0]
	}
	return result, scanner.Err()
}
