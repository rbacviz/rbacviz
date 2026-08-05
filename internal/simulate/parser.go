package simulate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const maxManifestBytes = 32 << 20

// LoadPath recursively loads YAML and JSON manifests in a deterministic order.
func LoadPath(path, defaultNamespace string) ([]Manifest, error) {
	files, err := manifestFiles(path)
	if err != nil {
		return nil, err
	}
	result := []Manifest{}
	for _, file := range files {
		values, err := loadFile(file, defaultNamespace)
		if err != nil {
			return nil, err
		}
		result = append(result, values...)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no Kubernetes manifest documents found in %q", path)
	}
	return result, nil
}

func manifestFiles(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect manifest path %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("manifest path %q must not be a symbolic link", path)
	}
	if !info.IsDir() {
		if !supportedExtension(path) {
			return nil, fmt.Errorf("manifest file %q must use .yaml, .yml, or .json", path)
		}
		return []string{path}, nil
	}
	files := []string{}
	err = filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() && supportedExtension(current) {
			files = append(files, current)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk manifest directory %q: %w", path, err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("manifest directory %q contains no .yaml, .yml, or .json files", path)
	}
	return files, nil
}

func supportedExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

func loadFile(path, defaultNamespace string) ([]Manifest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat manifest %q: %w", path, err)
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("manifest %q exceeds %d bytes", path, maxManifestBytes)
	}
	// #nosec G304 -- the CLI explicitly selects the offline manifest path.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := utilyaml.NewYAMLOrJSONDecoder(io.LimitReader(file, maxManifestBytes+1), 4096)
	result := []Manifest{}
	document := 0
	for {
		var raw map[string]any
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode manifest %q document %d: %w", path, document+1, err)
		}
		document++
		if len(raw) == 0 {
			continue
		}
		object := &unstructured.Unstructured{Object: raw}
		values, err := flattenObject(path, document, object, defaultNamespace)
		if err != nil {
			return nil, err
		}
		result = append(result, values...)
	}
	return result, nil
}

func flattenObject(source string, document int, object *unstructured.Unstructured, defaultNamespace string) ([]Manifest, error) {
	if object.GetKind() != "List" {
		value, err := convertObject(source, document, object, defaultNamespace)
		if err != nil {
			return nil, err
		}
		return []Manifest{value}, nil
	}
	items, found, err := unstructured.NestedSlice(object.Object, "items")
	if err != nil || !found {
		return nil, fmt.Errorf("manifest %q document %d has an invalid List.items field", source, document)
	}
	result := []Manifest{}
	for index, item := range items {
		raw, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("manifest %q document %d List item %d is not an object", source, document, index+1)
		}
		value, err := convertObject(source, document, &unstructured.Unstructured{Object: raw}, defaultNamespace)
		if err != nil {
			return nil, fmt.Errorf("list item %d: %w", index+1, err)
		}
		result = append(result, value)
	}
	return result, nil
}
