package baseline

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads one strict YAML or JSON baseline file. Unknown fields fail closed.
func Load(path string) (Document, error) {
	// #nosec G304 -- an explicit baseline path is an intentional CLI input.
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read baseline %q: %w", path, err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var value Document
	if err := decoder.Decode(&value); err != nil {
		return Document{}, fmt.Errorf("decode baseline %q: %w", path, err)
	}
	value.SchemaVersion = strings.TrimSpace(value.SchemaVersion)
	value.Profile = Profile(strings.ToLower(strings.TrimSpace(string(value.Profile))))
	for index := range value.Suppressions {
		normalizeSuppression(&value.Suppressions[index])
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple YAML documents are not allowed")
		}
		return Document{}, fmt.Errorf("decode baseline %q: %w", path, err)
	}
	if err := Validate(value); err != nil {
		return Document{}, fmt.Errorf("validate baseline %q: %w", path, err)
	}
	return value, nil
}
