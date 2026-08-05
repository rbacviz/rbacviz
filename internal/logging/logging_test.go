package logging_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rbacviz/rbacviz/internal/logging"
)

func TestNewFiltersAndWritesJSON(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger, err := logging.New("warn", &output)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logger.Info("hidden")
	logger.Warn("visible", "component", "test")

	got := output.String()
	if strings.Contains(got, "hidden") {
		t.Fatalf("output contains filtered message: %s", got)
	}
	if !strings.Contains(got, `"msg":"visible"`) || !strings.Contains(got, `"component":"test"`) {
		t.Fatalf("output is not expected structured JSON: %s", got)
	}
}

func TestContextRoundTrip(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger, err := logging.New("debug", &output)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := logging.WithContext(context.Background(), logger)
	logging.FromContext(ctx).Debug("round-trip")
	if !strings.Contains(output.String(), "round-trip") {
		t.Fatalf("logger was not recovered from context: %s", output.String())
	}
}
