package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxSnapshotBytes = 256 << 20

var forbiddenJSONKeys = map[string]struct{}{
	"data": {}, "stringdata": {}, "bearertoken": {}, "tokenfile": {},
	"clientkeydata": {}, "privatekey": {}, "privatekeydata": {},
}

// Marshal returns indented canonical JSON ending in a newline.
func Marshal(value Snapshot) ([]byte, error) {
	canonical, err := Canonicalize(value)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	return append(data, '\n'), nil
}

// Unmarshal validates sensitive-key absence and loads a compatible v1 snapshot.
func Unmarshal(data []byte) (Snapshot, error) {
	if len(data) > maxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	if err := rejectForbiddenKeys(data); err != nil {
		return Snapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value Snapshot
	if err := decoder.Decode(&value); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	canonical, err := Canonicalize(value)
	if err != nil {
		return Snapshot{}, fmt.Errorf("validate snapshot: %w", err)
	}
	return canonical, nil
}

// Load reads and validates a snapshot from disk.
func Load(path string) (Snapshot, error) {
	// #nosec G304 -- the CLI explicitly selects the offline snapshot path.
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open snapshot %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read snapshot %q: %w", path, err)
	}
	return Unmarshal(data)
}

// Save writes a canonical snapshot atomically with owner-only permissions.
func Save(path string, value Snapshot) error {
	data, err := Marshal(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".rbacviz-snapshot-*")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure snapshot permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace snapshot %q: %w", path, err)
	}
	keep = true
	return nil
}

func rejectForbiddenKeys(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil
	}
	var visit func(any) error
	visit = func(current any) error {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, forbidden := forbiddenJSONKeys[strings.ToLower(key)]; forbidden {
					return fmt.Errorf("snapshot contains forbidden sensitive field %q", key)
				}
				if err := visit(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(value)
}
