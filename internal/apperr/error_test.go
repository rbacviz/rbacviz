package apperr_test

import (
	"errors"
	"testing"

	"github.com/rbacviz/rbacviz/internal/apperr"
)

func TestExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", want: 0},
		{name: "operational", err: apperr.New(apperr.KindOperational, "test", "failed", nil), want: 1},
		{name: "validation", err: apperr.New(apperr.KindValidation, "test", "invalid", nil), want: 1},
		{name: "invalid input", err: apperr.New(apperr.KindInvalidInput, "test", "bad flag", nil), want: 2},
		{name: "partial", err: apperr.New(apperr.KindPartialCollection, "test", "partial", nil), want: 3},
		{name: "threshold", err: apperr.New(apperr.KindSecurityThreshold, "test", "gate", nil), want: 4},
		{name: "plain error", err: errors.New("plain"), want: 1},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := apperr.ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWrapPreservesKind(t *testing.T) {
	t.Parallel()

	inner := apperr.New(apperr.KindInvalidInput, "parse", "invalid value", errors.New("detail"))
	wrapped := apperr.Wrap("execute", inner)
	if got := apperr.ExitCode(wrapped); got != 2 {
		t.Fatalf("ExitCode() = %d, want 2", got)
	}
	if got := apperr.Message(wrapped); got != "invalid value" {
		t.Fatalf("Message() = %q, want %q", got, "invalid value")
	}
}
