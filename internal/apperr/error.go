// Package apperr defines errors that can cross an application boundary.
package apperr

import (
	"errors"
	"fmt"
)

// Kind identifies a stable class of failure without exposing implementation details.
type Kind string

const (
	// KindOperational represents an I/O or runtime failure.
	KindOperational Kind = "operational"
	// KindValidation represents invalid configuration or state.
	KindValidation Kind = "validation"
	// KindInvalidInput represents invalid CLI syntax, flags, or arguments.
	KindInvalidInput Kind = "invalid_input"
	// KindPartialCollection represents incomplete collection rejected by strict mode.
	KindPartialCollection Kind = "partial_collection"
	// KindSecurityThreshold represents a configured security gate being reached.
	KindSecurityThreshold Kind = "security_threshold"
)

// Error is the typed error returned by application and interface boundaries.
type Error struct {
	Kind    Kind
	Op      string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return string(e.Kind)
}

func (e *Error) Unwrap() error { return e.Err }

// New creates a typed error with a user-safe message.
func New(kind Kind, op, message string, err error) error {
	return &Error{Kind: kind, Op: op, Message: message, Err: err}
}

// Wrap annotates an error while keeping its typed classification when present.
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var appErr *Error
	if errors.As(err, &appErr) {
		return &Error{
			Kind:    appErr.Kind,
			Op:      joinOp(op, appErr.Op),
			Message: appErr.Message,
			Err:     err,
		}
	}
	return &Error{Kind: KindOperational, Op: op, Message: err.Error(), Err: err}
}

// IsTyped reports whether err has an application error classification.
func IsTyped(err error) bool {
	var appErr *Error
	return errors.As(err, &appErr)
}

// ExitCode maps application failures to the public CLI contract.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var appErr *Error
	if !errors.As(err, &appErr) {
		return 1
	}
	switch appErr.Kind {
	case KindInvalidInput:
		return 2
	case KindPartialCollection:
		return 3
	case KindSecurityThreshold:
		return 4
	case KindOperational, KindValidation:
		return 1
	default:
		return 1
	}
}

// Message returns the safe text intended for a CLI user.
func Message(err error) string {
	if err == nil {
		return ""
	}
	var appErr *Error
	if errors.As(err, &appErr) && appErr.Message != "" {
		return appErr.Message
	}
	return err.Error()
}

func joinOp(parent, child string) string {
	switch {
	case parent == "":
		return child
	case child == "":
		return parent
	default:
		return fmt.Sprintf("%s: %s", parent, child)
	}
}
