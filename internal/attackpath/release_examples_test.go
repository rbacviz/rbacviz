package attackpath

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestReleaseExampleHostEscapeIsBlocked(t *testing.T) {
	value, err := snapshot.Load(filepath.Join("..", "..", "examples", "clusters", "host-escape-blocked.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Analyze(context.Background(), Query{Top: 100, MaxExpanded: 1000})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range result.Paths {
		if path.Target.Type == TargetHostEscape {
			found = true
			if !path.Blocked || path.Confidence != ConfidenceBlocked {
				t.Fatalf("host escape path was not blocked: %+v", path)
			}
		}
	}
	if !found {
		t.Fatal("host escape example produced no host escape path")
	}
}

func TestReleaseExamplePreservesPartialCollection(t *testing.T) {
	value, err := snapshot.Load(filepath.Join("..", "..", "examples", "clusters", "partial-collection.json"))
	if err != nil {
		t.Fatal(err)
	}
	if value.Metadata.Complete || len(value.Warnings) != 1 {
		t.Fatalf("partial example lost completeness evidence: %+v", value.Metadata)
	}
}
