// Package logging configures structured application logging.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

type contextKey struct{}

// New creates a JSON logger at the requested minimum level.
func New(level string, writer io.Writer) (*slog.Logger, error) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("unsupported log level %q", level)
	}
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slogLevel})), nil
}

// WithContext stores the command-scoped logger without using mutable globals.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// FromContext returns the command logger or a discard logger when none was set.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(contextKey{}).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
