package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/report"
	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestReportCommandWritesMarkdownAndJSON(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "cluster.json")
	if err := snapshot.Save(snapshotPath, riskCLISnapshot()); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "report.md")
	code, stdout, stderr := execute("report", "--snapshot", snapshotPath, "--format", "md", "--file", reportPath, "--max-candidates", "20", "--max-paths", "100", "--max-expanded", "1000")
	if code != 0 || stderr != "" {
		t.Fatalf("code = %d stdout = %q stderr = %q", code, stdout, stderr)
	}
	// #nosec G304 -- reportPath is created by t.TempDir in this test.
	payload, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "# RBACVIZ Kubernetes RBAC Security Report") || !strings.Contains(stdout, "root causes:") {
		t.Fatalf("stdout = %q report = %q", stdout, payload)
	}

	code, stdout, stderr = execute("report", "--snapshot", snapshotPath, "--format", "json", "--max-candidates", "20", "--max-paths", "100", "--max-expanded", "1000")
	if code != 0 || stderr != "" {
		t.Fatalf("JSON code = %d stderr = %q", code, stderr)
	}
	var result report.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid report JSON: %v\n%s", err, stdout)
	}
	if result.SchemaVersion != report.ResultSchemaVersion || result.Summary.RootCauses == 0 {
		t.Fatalf("unexpected report contract: %+v", result)
	}
}

func TestReportCommandRejectsInvalidBoundsAndFormat(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"report", "--format", "pdf"},
		{"report", "--max-issues", "0"},
		{"report", "--max-candidates", "0"},
		{"report", "--max-paths", "0"},
		{"report", "--max-expanded", "0"},
	} {
		code, _, stderr := execute(args...)
		if code != 2 || stderr == "" {
			t.Fatalf("args = %v code = %d stderr = %q", args, code, stderr)
		}
	}
}

func TestReportCommandWritesRootCauseSARIF(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "cluster.json")
	if err := snapshot.Save(snapshotPath, riskCLISnapshot()); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute("report", "--snapshot", snapshotPath, "--format", "sarif", "--max-candidates", "20", "--max-paths", "100", "--max-expanded", "1000")
	if code != 0 || stderr != "" {
		t.Fatalf("SARIF code = %d stderr = %q", code, stderr)
	}
	var payload struct {
		Version string `json:"version"`
		Runs    []struct {
			Results    []json.RawMessage `json:"results"`
			Properties struct {
				ReportSchemaVersion string `json:"reportSchemaVersion"`
				ReportModelVersion  string `json:"reportModelVersion"`
			} `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid report SARIF: %v\n%s", err, stdout)
	}
	if payload.Version != "2.1.0" || len(payload.Runs) != 1 || len(payload.Runs[0].Results) == 0 ||
		payload.Runs[0].Properties.ReportSchemaVersion != report.ResultSchemaVersion ||
		payload.Runs[0].Properties.ReportModelVersion != report.ModelVersion {
		t.Fatalf("unexpected report SARIF contract: %+v", payload)
	}
}

func TestReportCommandAppliesStrictReviewedBaseline(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "cluster.json")
	if err := snapshot.Save(snapshotPath, riskCLISnapshot()); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(directory, "baseline.yaml")
	payload := "schemaVersion: '1.0'\nprofile: development\nsuppressions:\n  - id: token-minter-reviewed\n    rule: RBACVIZ-R009\n    subject: user:alice\n    reason: Required by the synthetic deployment workflow\n    owner: platform-security\n    expires: '2099-10-01'\n"
	if err := os.WriteFile(baselinePath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute("report", "--snapshot", snapshotPath, "--format", "json", "--baseline", baselinePath, "--max-candidates", "20", "--max-paths", "100", "--max-expanded", "1000")
	if code != 0 || stderr != "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	var result report.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.Summary.AcceptedExceptions != 1 || len(result.AcceptedExceptions) != 1 || len(result.AcceptedExceptions[0].Issues) == 0 {
		t.Fatalf("baseline not applied: %+v", result)
	}

	badPath := filepath.Join(directory, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("schemaVersion: '1.0'\nprofile: development\nsuppressions:\n- id: broad\n  rule: 'RBACVIZ-*'\n  reason: too broad\n  owner: nobody\n  expires: '2099-01-01'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = execute("report", "--snapshot", snapshotPath, "--baseline", badPath)
	if code != 2 || !strings.Contains(stderr, "selectors must be exact") {
		t.Fatalf("invalid baseline code=%d stderr=%q", code, stderr)
	}
}
