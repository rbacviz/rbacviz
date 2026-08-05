package remediation

import (
	"context"
	"encoding/json"
	"testing"
)

func FuzzGenerateDeterministic(f *testing.F) {
	f.Add("alice", uint8(2))
	f.Fuzz(func(t *testing.T, name string, limit uint8) {
		if name == "" {
			return
		}
		value := tokenSnapshot()
		value.Bindings[0].Subjects[0].Name = name
		options := Options{MaxCandidates: int(limit%8) + 1, MaxPaths: 100, MaxExpanded: 1000}
		first, err := Generate(context.Background(), value, options)
		if err != nil {
			return
		}
		second, err := Generate(context.Background(), value, options)
		if err != nil {
			t.Fatal(err)
		}
		left, _ := json.Marshal(first)
		right, _ := json.Marshal(second)
		if string(left) != string(right) {
			t.Fatal("non-deterministic remediation result")
		}
	})
}
