package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
)

// Module is the dependency information emitted by `go list -m -json all`.
type Module struct {
	Path    string  `json:"Path"`
	Version string  `json:"Version"`
	Sum     string  `json:"Sum"`
	Main    bool    `json:"Main"`
	Replace *Module `json:"Replace"`
}

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     bomMetadata `json:"metadata"`
	Components   []component `json:"components"`
}

type bomMetadata struct {
	Timestamp string    `json:"timestamp"`
	Component component `json:"component"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl"`
	BOMRef  string `json:"bom-ref"`
	Hashes  []hash `json:"hashes,omitempty"`
}

type hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// CycloneDX returns a deterministic CycloneDX 1.5 module SBOM.
func CycloneDX(product, version, timestamp string, modules []Module) ([]byte, error) {
	if product == "" || version == "" || timestamp == "" {
		return nil, fmt.Errorf("product, version, and timestamp are required")
	}
	main := component{Type: "application", Name: product, Version: version, PURL: purl(product, version), BOMRef: purl(product, version)}
	components := make([]component, 0, len(modules))
	for _, module := range modules {
		if module.Main {
			continue
		}
		resolved := module
		if module.Replace != nil {
			resolved = *module.Replace
		}
		if resolved.Path == "" {
			continue
		}
		value := component{Type: "library", Name: resolved.Path, Version: resolved.Version, PURL: purl(resolved.Path, resolved.Version), BOMRef: purl(resolved.Path, resolved.Version)}
		if digest := goSumDigest(resolved.Sum); digest != "" {
			value.Hashes = []hash{{Algorithm: "SHA-256", Content: digest}}
		}
		components = append(components, value)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })
	identifier := sha256.Sum256([]byte(product + "\x00" + version))
	identifier[6] = (identifier[6] & 0x0f) | 0x50
	identifier[8] = (identifier[8] & 0x3f) | 0x80
	serial := fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", hex.EncodeToString(identifier[0:4]), hex.EncodeToString(identifier[4:6]), hex.EncodeToString(identifier[6:8]), hex.EncodeToString(identifier[8:10]), hex.EncodeToString(identifier[10:16]))
	value := bom{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: serial, Version: 1, Metadata: bomMetadata{Timestamp: timestamp, Component: main}, Components: components}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func purl(path, version string) string {
	value := "pkg:golang/" + url.PathEscape(path)
	if version != "" {
		value += "@" + url.PathEscape(version)
	}
	return value
}

// h1 Go module sums are base64, not SHA-256 hex. CycloneDX permits hashes only
// in hex or base64; retaining the base64 payload would violate its content rule,
// so release generation omits it rather than mislabeling it.
func goSumDigest(sum string) string {
	_ = sum
	return ""
}
