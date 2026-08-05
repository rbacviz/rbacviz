// Package config loads and validates immutable runtime configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rbacviz/rbacviz/internal/apperr"
)

const (
	// DefaultLogLevel is the minimum structured log severity.
	DefaultLogLevel = "info"
	// DefaultOutput is the interactive human-readable output format.
	DefaultOutput = "human"
	// DefaultTimeout bounds command execution unless the user overrides it.
	DefaultTimeout = 30 * time.Second
)

// Source records where an effective setting came from.
type Source string

const (
	// SourceDefault indicates a built-in default.
	SourceDefault Source = "default"
	// SourceFile indicates a value read from the JSON configuration file.
	SourceFile Source = "file"
	// SourceEnv indicates an RBACVIZ_* environment override.
	SourceEnv Source = "environment"
	// SourceFlag indicates an explicit CLI flag, the highest precedence source.
	SourceFlag Source = "flag"
)

// Config is the immutable configuration consumed by application commands.
type Config struct {
	Context       string        `json:"context,omitempty"`
	Kubeconfig    string        `json:"kubeconfig,omitempty"`
	Namespace     string        `json:"namespace,omitempty"`
	AllNamespaces bool          `json:"allNamespaces"`
	Snapshot      string        `json:"snapshot,omitempty"`
	Output        string        `json:"output"`
	NoColor       bool          `json:"noColor"`
	Timeout       time.Duration `json:"-"`
	LogLevel      string        `json:"logLevel"`
}

// MarshalJSON renders durations as portable strings.
func (c Config) MarshalJSON() ([]byte, error) {
	type wireConfig struct {
		Context       string `json:"context,omitempty"`
		Kubeconfig    string `json:"kubeconfig,omitempty"`
		Namespace     string `json:"namespace,omitempty"`
		AllNamespaces bool   `json:"allNamespaces"`
		Snapshot      string `json:"snapshot,omitempty"`
		Output        string `json:"output"`
		NoColor       bool   `json:"noColor"`
		Timeout       string `json:"timeout"`
		LogLevel      string `json:"logLevel"`
	}
	return json.Marshal(wireConfig{
		Context: c.Context, Kubeconfig: c.Kubeconfig, Namespace: c.Namespace,
		AllNamespaces: c.AllNamespaces, Snapshot: c.Snapshot, Output: c.Output,
		NoColor: c.NoColor, Timeout: c.Timeout.String(), LogLevel: c.LogLevel,
	})
}

// Result includes the effective configuration and provenance for every setting.
type Result struct {
	Config  Config            `json:"config"`
	Sources map[string]Source `json:"sources"`
	File    string            `json:"file,omitempty"`
}

// Overrides contains only flags explicitly provided by the user.
type Overrides struct {
	Context       *string
	Kubeconfig    *string
	Namespace     *string
	AllNamespaces *bool
	Snapshot      *string
	Output        *string
	NoColor       *bool
	Timeout       *time.Duration
	LogLevel      *string
}

// LoadOptions injects all external inputs, keeping loading deterministic in tests.
type LoadOptions struct {
	FilePath     string
	FileRequired bool
	LookupEnv    func(string) (string, bool)
	Overrides    Overrides
}

type fileConfig struct {
	Context       *string `json:"context"`
	Kubeconfig    *string `json:"kubeconfig"`
	Namespace     *string `json:"namespace"`
	AllNamespaces *bool   `json:"allNamespaces"`
	Snapshot      *string `json:"snapshot"`
	Output        *string `json:"output"`
	NoColor       *bool   `json:"noColor"`
	Timeout       *string `json:"timeout"`
	LogLevel      *string `json:"logLevel"`
}

// Load applies defaults, file, environment, and explicit flags in that order.
func Load(options LoadOptions) (Result, error) {
	lookupEnv := options.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	result := defaultResult()
	result.File = options.FilePath
	if err := applyFile(&result, options.FilePath, options.FileRequired); err != nil {
		return Result{}, err
	}
	if err := applyEnvironment(&result, lookupEnv); err != nil {
		return Result{}, err
	}
	applyOverrides(&result, options.Overrides)
	if err := Validate(result.Config); err != nil {
		return Result{}, err
	}
	return result, nil
}

// DefaultPath follows the operating system's standard user configuration directory.
func DefaultPath(userConfigDir func() (string, error)) (string, error) {
	if userConfigDir == nil {
		userConfigDir = os.UserConfigDir
	}
	dir, err := userConfigDir()
	if err != nil {
		return "", apperr.New(apperr.KindOperational, "config.default_path", "cannot determine the user configuration directory", err)
	}
	return filepath.Join(dir, "rbacviz", "config.json"), nil
}

// Validate checks conflicts and all bounded values before commands use them.
func Validate(cfg Config) error {
	if cfg.Namespace != "" && cfg.AllNamespaces {
		return apperr.New(apperr.KindValidation, "config.validate", "--namespace and --all-namespaces cannot be used together", nil)
	}
	if cfg.Snapshot != "" && (cfg.Context != "" || cfg.Kubeconfig != "") {
		return apperr.New(apperr.KindValidation, "config.validate", "--snapshot cannot be combined with --context or --kubeconfig", nil)
	}
	if cfg.Timeout <= 0 {
		return apperr.New(apperr.KindValidation, "config.validate", "timeout must be greater than zero", nil)
	}
	if !oneOf(cfg.Output, "human", "json", "sarif") {
		return apperr.New(apperr.KindValidation, "config.validate", "output must be one of: human, json, sarif", nil)
	}
	if !oneOf(cfg.LogLevel, "debug", "info", "warn", "error") {
		return apperr.New(apperr.KindValidation, "config.validate", "log level must be one of: debug, info, warn, error", nil)
	}
	return nil
}

func defaultResult() Result {
	sources := make(map[string]Source, 9)
	for _, key := range settingKeys() {
		sources[key] = SourceDefault
	}
	return Result{
		Config:  Config{Output: DefaultOutput, Timeout: DefaultTimeout, LogLevel: DefaultLogLevel},
		Sources: sources,
	}
}

func applyFile(result *Result, path string, required bool) error {
	if path == "" {
		return nil
	}
	// #nosec G304 -- selecting a configuration path is an intentional CLI feature.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !required {
			return nil
		}
		return apperr.New(apperr.KindOperational, "config.read", fmt.Sprintf("cannot read config file %q", path), err)
	}
	var file fileConfig
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return apperr.New(apperr.KindValidation, "config.decode", fmt.Sprintf("invalid config file %q: %v", path, err), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return apperr.New(apperr.KindValidation, "config.decode", fmt.Sprintf("invalid config file %q: %v", path, err), err)
	}
	return applyFileValues(result, file)
}

func applyFileValues(result *Result, file fileConfig) error {
	setString(&result.Config.Context, file.Context, result.Sources, "context", SourceFile)
	setString(&result.Config.Kubeconfig, file.Kubeconfig, result.Sources, "kubeconfig", SourceFile)
	setString(&result.Config.Namespace, file.Namespace, result.Sources, "namespace", SourceFile)
	setBool(&result.Config.AllNamespaces, file.AllNamespaces, result.Sources, "allNamespaces", SourceFile)
	setString(&result.Config.Snapshot, file.Snapshot, result.Sources, "snapshot", SourceFile)
	setString(&result.Config.Output, file.Output, result.Sources, "output", SourceFile)
	setBool(&result.Config.NoColor, file.NoColor, result.Sources, "noColor", SourceFile)
	setString(&result.Config.LogLevel, file.LogLevel, result.Sources, "logLevel", SourceFile)
	if file.Timeout != nil {
		value, err := time.ParseDuration(*file.Timeout)
		if err != nil {
			return apperr.New(apperr.KindValidation, "config.timeout", fmt.Sprintf("invalid timeout %q in config file", *file.Timeout), err)
		}
		result.Config.Timeout = value
		result.Sources["timeout"] = SourceFile
	}
	return nil
}

func applyEnvironment(result *Result, lookup func(string) (string, bool)) error {
	applyEnvString(&result.Config.Context, result.Sources, "context", "RBACVIZ_CONTEXT", lookup)
	applyEnvString(&result.Config.Kubeconfig, result.Sources, "kubeconfig", "RBACVIZ_KUBECONFIG", lookup)
	applyEnvString(&result.Config.Namespace, result.Sources, "namespace", "RBACVIZ_NAMESPACE", lookup)
	applyEnvString(&result.Config.Snapshot, result.Sources, "snapshot", "RBACVIZ_SNAPSHOT", lookup)
	applyEnvString(&result.Config.Output, result.Sources, "output", "RBACVIZ_OUTPUT", lookup)
	applyEnvString(&result.Config.LogLevel, result.Sources, "logLevel", "RBACVIZ_LOG_LEVEL", lookup)

	if value, ok := lookup("RBACVIZ_ALL_NAMESPACES"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return invalidEnv("RBACVIZ_ALL_NAMESPACES", value, err)
		}
		result.Config.AllNamespaces = parsed
		result.Sources["allNamespaces"] = SourceEnv
	}
	if value, ok := lookup("RBACVIZ_NO_COLOR"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return invalidEnv("RBACVIZ_NO_COLOR", value, err)
		}
		result.Config.NoColor = parsed
		result.Sources["noColor"] = SourceEnv
	}
	if value, ok := lookup("RBACVIZ_TIMEOUT"); ok {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return invalidEnv("RBACVIZ_TIMEOUT", value, err)
		}
		result.Config.Timeout = parsed
		result.Sources["timeout"] = SourceEnv
	}
	return nil
}

func applyOverrides(result *Result, values Overrides) {
	setString(&result.Config.Context, values.Context, result.Sources, "context", SourceFlag)
	setString(&result.Config.Kubeconfig, values.Kubeconfig, result.Sources, "kubeconfig", SourceFlag)
	setString(&result.Config.Namespace, values.Namespace, result.Sources, "namespace", SourceFlag)
	setBool(&result.Config.AllNamespaces, values.AllNamespaces, result.Sources, "allNamespaces", SourceFlag)
	setString(&result.Config.Snapshot, values.Snapshot, result.Sources, "snapshot", SourceFlag)
	setString(&result.Config.Output, values.Output, result.Sources, "output", SourceFlag)
	setBool(&result.Config.NoColor, values.NoColor, result.Sources, "noColor", SourceFlag)
	setDuration(&result.Config.Timeout, values.Timeout, result.Sources, "timeout", SourceFlag)
	setString(&result.Config.LogLevel, values.LogLevel, result.Sources, "logLevel", SourceFlag)
}

func applyEnvString(destination *string, sources map[string]Source, key, environment string, lookup func(string) (string, bool)) {
	if value, ok := lookup(environment); ok {
		*destination = value
		sources[key] = SourceEnv
	}
}

func setString(destination *string, value *string, sources map[string]Source, key string, source Source) {
	if value != nil {
		*destination = *value
		sources[key] = source
	}
}

func setBool(destination *bool, value *bool, sources map[string]Source, key string, source Source) {
	if value != nil {
		*destination = *value
		sources[key] = source
	}
}

func setDuration(destination *time.Duration, value *time.Duration, sources map[string]Source, key string, source Source) {
	if value != nil {
		*destination = *value
		sources[key] = source
	}
}

func invalidEnv(name, value string, err error) error {
	return apperr.New(apperr.KindValidation, "config.environment", fmt.Sprintf("invalid value %q for %s", value, name), err)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func settingKeys() []string {
	return []string{"context", "kubeconfig", "namespace", "allNamespaces", "snapshot", "output", "noColor", "timeout", "logLevel"}
}
