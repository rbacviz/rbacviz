// Package sarif renders analysis findings as deterministic SARIF 2.1.0 for CI
// and code-scanning consumers.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/rbacviz/rbacviz/internal/analysis"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

const schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

type report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool       tool          `json:"tool"`
	Results    []result      `json:"results"`
	Properties runProperties `json:"properties"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string           `json:"name"`
	InformationURI string           `json:"informationUri"`
	Rules          []ruleDescriptor `json:"rules"`
}

type ruleDescriptor struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription message        `json:"shortDescription"`
	FullDescription  message        `json:"fullDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       ruleProperties `json:"properties"`
}

type ruleProperties struct {
	SecuritySeverity string   `json:"security-severity"`
	Severity         string   `json:"severity"`
	Tags             []string `json:"tags"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          resultProperties  `json:"properties"`
}

type resultProperties struct {
	Finding analysis.Finding `json:"finding"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type runProperties struct {
	SchemaVersion  string             `json:"schemaVersion"`
	RulesetVersion string             `json:"rulesetVersion"`
	Complete       bool               `json:"complete"`
	Warnings       []analysis.Warning `json:"warnings"`
}

// Write serializes one complete findings result as SARIF 2.1.0.
func Write(writer io.Writer, findings analysis.Result) error {
	rules := make([]ruleDescriptor, 0, len(findings.Rules))
	for _, metadata := range findings.Rules {
		help := ""
		if len(metadata.References) > 0 {
			help = metadata.References[0]
		}
		rules = append(rules, ruleDescriptor{
			ID: metadata.ID, Name: sarifName(metadata.ID),
			ShortDescription: message{Text: metadata.Title}, FullDescription: message{Text: metadata.Description},
			HelpURI:    help,
			Properties: ruleProperties{SecuritySeverity: fmt.Sprintf("%.1f", float64(metadata.RiskScore)/10), Severity: strings.ToLower(string(metadata.Severity)), Tags: []string{"security", "kubernetes", "rbac"}},
		})
	}
	results := make([]result, 0, len(findings.Findings))
	for _, finding := range findings.Findings {
		locations := make([]location, 0, len(finding.AffectedObjects))
		for _, ref := range finding.AffectedObjects {
			locations = append(locations, location{PhysicalLocation: physicalLocation{ArtifactLocation: artifactLocation{URI: kubernetesURI(ref)}}})
		}
		results = append(results, result{
			RuleID: finding.RuleID, Level: sarifLevel(finding.Severity),
			Message: message{Text: finding.Title + ": " + finding.Description}, Locations: locations,
			PartialFingerprints: map[string]string{"rbacvizFindingId/v1": finding.ID},
			Properties:          resultProperties{Finding: finding},
		})
	}
	payload := report{Version: "2.1.0", Schema: schemaURI, Runs: []run{{
		Tool:       tool{Driver: driver{Name: "rbacviz", InformationURI: "https://github.com/rbacviz/rbacviz", Rules: rules}},
		Results:    results,
		Properties: runProperties{SchemaVersion: findings.SchemaVersion, RulesetVersion: findings.RulesetVersion, Complete: findings.Complete, Warnings: findings.Warnings},
	}}}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func sarifLevel(value analysis.Severity) string {
	switch value {
	case analysis.SeverityCritical, analysis.SeverityHigh:
		return "error"
	case analysis.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifName(id string) string { return strings.ReplaceAll(id, "-", "_") }

func kubernetesURI(ref snapshot.ObjectRef) string {
	group := ref.APIGroup
	if group == "" {
		group = "core"
	}
	parts := []string{url.PathEscape(group), url.PathEscape(ref.Kind)}
	if ref.Namespace != "" {
		parts = append(parts, url.PathEscape(ref.Namespace))
	}
	parts = append(parts, url.PathEscape(ref.Name))
	return "kubernetes:///" + strings.Join(parts, "/")
}
