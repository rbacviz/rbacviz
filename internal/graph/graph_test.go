package graph

import (
	"context"
	"reflect"
	"testing"

	"github.com/rbacviz/rbacviz/internal/snapshot"
)

func TestGraphIndexesSelectorsAndStats(t *testing.T) {
	t.Parallel()
	graph := mustGraph(t,
		[]Node{
			{ID: "b", Type: NodeRole, Key: "role:prod:reader", Name: "reader", Namespace: "prod", Kind: "Role"},
			{ID: "a", Type: NodeIdentity, Key: "identity:user:alice", Name: "alice", Kind: "User"},
		},
		[]Edge{{ID: "edge", From: "a", To: "b", Relation: RelationBoundBy, Evidence: []Evidence{{Kind: "test"}}, Confidence: ConfidenceConfirmed, Cost: 1}},
	)
	nodes := graph.Select(Selector{Types: []NodeType{NodeRole}, Namespace: "prod"})
	if len(nodes) != 1 || nodes[0].ID != "b" {
		t.Fatalf("Select() = %#v", nodes)
	}
	resolved, err := graph.Resolve("identity:user:alice")
	if err != nil || resolved.ID != "a" {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
	stats := graph.Stats()
	if stats.Nodes != 2 || stats.Edges != 1 || len(stats.NodesByType) != 2 {
		t.Fatalf("Stats() = %#v", stats)
	}
}

func TestGraphRejectsInvalidEdges(t *testing.T) {
	t.Parallel()
	_, err := New([]Node{{ID: "a", Type: NodeIdentity, Key: "a"}}, []Edge{{ID: "bad", From: "a", To: "missing", Relation: RelationReaches, Evidence: []Evidence{{Kind: "test"}}}}, nil)
	if err == nil {
		t.Fatal("New() accepted a missing endpoint")
	}
	_, err = New([]Node{{ID: "a", Type: NodeIdentity, Key: "a"}}, []Edge{{ID: "bad", From: "a", To: "a", Relation: RelationReaches}}, nil)
	if err == nil {
		t.Fatal("New() accepted an edge without evidence")
	}
}

func TestTopKPathsAreWeightedLooplessAndDeterministic(t *testing.T) {
	t.Parallel()
	nodes := []Node{
		{ID: "a", Type: NodeIdentity, Key: "a"}, {ID: "b", Type: NodeRole, Key: "b"},
		{ID: "c", Type: NodeRole, Key: "c"}, {ID: "d", Type: NodeResourceSelector, Key: "d"},
	}
	edges := []Edge{
		testEdge("ab", "a", "b", 1), testEdge("bd", "b", "d", 1),
		testEdge("ac", "a", "c", 1), testEdge("cd", "c", "d", 2),
		testEdge("ad", "a", "d", 5), testEdge("ca", "c", "a", 0),
	}
	graph := mustGraph(t, nodes, edges)
	result, err := graph.TopKPaths(context.Background(), "a", "d", PathLimits{K: 3, MaxDepth: 6, MaxExpanded: 100})
	if err != nil {
		t.Fatalf("TopKPaths() error = %v", err)
	}
	costs := []uint64{result.Paths[0].Cost, result.Paths[1].Cost, result.Paths[2].Cost}
	if !reflect.DeepEqual(costs, []uint64{2, 3, 5}) {
		t.Fatalf("path costs = %v", costs)
	}
	for _, path := range result.Paths {
		seen := make(map[string]struct{})
		for _, node := range path.Nodes {
			if _, exists := seen[node.ID]; exists {
				t.Fatalf("cyclic path returned: %#v", path)
			}
			seen[node.ID] = struct{}{}
		}
	}
	again, _ := graph.TopKPaths(context.Background(), "a", "d", PathLimits{K: 3, MaxDepth: 6, MaxExpanded: 100})
	if !reflect.DeepEqual(result, again) {
		t.Fatal("TopKPaths() is not deterministic")
	}
}

func TestTraversalAndPathBounds(t *testing.T) {
	t.Parallel()
	graph := mustGraph(t,
		[]Node{{ID: "a", Type: NodeIdentity, Key: "a"}, {ID: "b", Type: NodeRole, Key: "b"}, {ID: "c", Type: NodeRole, Key: "c"}},
		[]Edge{testEdge("ab", "a", "b", 1), testEdge("bc", "b", "c", 1)},
	)
	traversal, err := graph.Traverse(context.Background(), "a", DirectionOutgoing, TraversalLimits{MaxDepth: 3, MaxExpanded: 1})
	if err != nil || !traversal.Truncated || len(traversal.Nodes) != 2 {
		t.Fatalf("Traverse() = %#v, %v", traversal, err)
	}
	paths, err := graph.TopKPaths(context.Background(), "a", "c", PathLimits{K: 1, MaxDepth: 4, MaxExpanded: 1})
	if err != nil || !paths.Truncated || len(paths.Paths) != 0 {
		t.Fatalf("bounded TopKPaths() = %#v, %v", paths, err)
	}
}

func TestTopKPreservesParallelEvidencePathsAndCancellation(t *testing.T) {
	t.Parallel()
	graph := mustGraph(t,
		[]Node{{ID: "a", Type: NodeIdentity, Key: "a"}, {ID: "b", Type: NodeRole, Key: "b"}, {ID: "c", Type: NodeResourceSelector, Key: "c"}},
		[]Edge{testEdge("grant-one", "a", "b", 1), testEdge("grant-two", "a", "b", 1), testEdge("target", "b", "c", 1)},
	)
	paths, err := graph.TopKPaths(context.Background(), "a", "c", PathLimits{K: 3, MaxDepth: 4, MaxExpanded: 100})
	if err != nil || len(paths.Paths) != 2 || paths.Paths[0].ID == paths.Paths[1].ID {
		t.Fatalf("parallel evidence paths = %#v, %v", paths, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := graph.TopKPaths(ctx, "a", "c", PathLimits{}); err == nil {
		t.Fatal("TopKPaths() ignored cancellation")
	}
}

func TestBuildCreatesEvidenceBackedLazyPermissionPath(t *testing.T) {
	t.Parallel()
	value := graphFixture()
	first, err := Build(value)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	second, err := Build(value)
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	if !reflect.DeepEqual(first.Nodes(), second.Nodes()) || !reflect.DeepEqual(first.Edges(), second.Edges()) {
		t.Fatal("Build() is not deterministic")
	}
	identity, err := first.Resolve("identity:user:alice")
	if err != nil {
		t.Fatal(err)
	}
	selectors := first.Select(Selector{Types: []NodeType{NodeResourceSelector}, Namespace: "prod", Name: "pods"})
	if len(selectors) != 1 {
		t.Fatalf("resource selectors = %#v", selectors)
	}
	paths, err := first.TopKPaths(context.Background(), identity.ID, selectors[0].ID, PathLimits{K: 10, MaxDepth: 8, MaxExpanded: 1000})
	if err != nil || len(paths.Paths) == 0 {
		t.Fatalf("permission path = %#v, %v", paths, err)
	}
	for _, edge := range paths.Paths[0].Edges {
		if len(edge.Evidence) == 0 {
			t.Fatalf("edge lacks evidence: %#v", edge)
		}
	}
	if first.Stats().NodesByType == nil {
		t.Fatal("missing typed node counts")
	}
	if len(first.Select(Selector{Types: []NodeType{NodeNamespace}})) != 1 || len(first.Select(Selector{Types: []NodeType{NodeSecurityControl}})) != 1 {
		t.Fatal("namespace and its security-control observation were not modeled as distinct typed nodes")
	}
}

func BenchmarkTopKPathsSynthetic(b *testing.B) {
	nodes := make([]Node, 1001)
	for index := range nodes {
		nodes[index] = Node{ID: stableID("bench-node", string(rune(index))), Type: NodeCapability, Key: stableID("key", string(rune(index)))}
	}
	edges := make([]Edge, 0, 2000)
	for index := 0; index < 1000; index++ {
		edges = append(edges, testEdge(stableID("edge", nodes[index].ID, nodes[index+1].ID), nodes[index].ID, nodes[index+1].ID, 1))
		if index+10 < len(nodes) {
			edges = append(edges, testEdge(stableID("skip", nodes[index].ID), nodes[index].ID, nodes[index+10].ID, 2))
		}
	}
	graph, err := New(nodes, edges, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_, err := graph.TopKPaths(context.Background(), nodes[0].ID, nodes[len(nodes)-1].ID, PathLimits{K: 3, MaxDepth: 120, MaxExpanded: 100000})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzTopKPaths(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6})
	f.Add([]byte{0, 0, 1, 1, 2, 2, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		const count = 8
		nodes := make([]Node, count)
		for index := range nodes {
			nodes[index] = Node{ID: string(rune('a' + index)), Type: NodeCapability, Key: "node:" + string(rune('a'+index))}
		}
		edges := make([]Edge, 0, len(data)/2)
		for index := 0; index+1 < len(data) && len(edges) < 32; index += 2 {
			from := int(data[index]) % count
			to := int(data[index+1]) % count
			id := stableID("fuzz-edge", string(rune(index)), nodes[from].ID, nodes[to].ID)
			edges = append(edges, testEdge(id, nodes[from].ID, nodes[to].ID, uint32(data[index]%5)))
		}
		graph, err := New(nodes, edges, nil)
		if err != nil {
			t.Skip()
		}
		result, err := graph.TopKPaths(context.Background(), nodes[0].ID, nodes[count-1].ID, PathLimits{K: 5, MaxDepth: count, MaxExpanded: 1000})
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range result.Paths {
			seen := make(map[string]struct{})
			for _, node := range path.Nodes {
				if _, exists := seen[node.ID]; exists {
					t.Fatalf("cyclic path: %#v", path)
				}
				seen[node.ID] = struct{}{}
			}
		}
	})
}

func mustGraph(t *testing.T, nodes []Node, edges []Edge) *Graph {
	t.Helper()
	graph, err := New(nodes, edges, nil)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func testEdge(id, from, to string, cost uint32) Edge {
	return Edge{ID: id, From: from, To: to, Relation: RelationReaches, Evidence: []Evidence{{Kind: "test"}}, Confidence: ConfidenceConfirmed, Cost: cost, Prerequisites: []string{}}
}

func graphFixture() snapshot.Snapshot {
	return snapshot.Snapshot{
		SchemaVersion: snapshot.SchemaVersion, ToolVersion: "test",
		Metadata:         snapshot.Metadata{CollectedAt: "2026-08-05T12:00:00Z", AllNamespaces: true, Complete: true},
		APIResources:     []snapshot.APIResource{{GroupVersion: "v1", Version: "v1", Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get"}}},
		Roles:            []snapshot.Role{{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"}, Rules: []snapshot.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}}}},
		Bindings:         []snapshot.Binding{{Ref: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "RoleBinding", Namespace: "prod", Name: "readers"}, RoleRef: snapshot.ObjectRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Namespace: "prod", Name: "reader"}, Subjects: []snapshot.Subject{{Kind: snapshot.IdentityUser, Name: "alice"}}}},
		ServiceAccounts:  []snapshot.ServiceAccount{{Ref: snapshot.ObjectRef{Kind: "ServiceAccount", Namespace: "prod", Name: "api"}}},
		Workloads:        []snapshot.Workload{{Ref: snapshot.ObjectRef{APIGroup: "apps", Kind: "Deployment", Namespace: "prod", Name: "api"}, ServiceAccountName: "api", Volumes: []snapshot.VolumeReference{{Name: "config", Kind: "Secret", Namespace: "prod", Target: "api-config"}}}},
		Assets:           []snapshot.Asset{{Ref: snapshot.ObjectRef{Kind: "Secret", Namespace: "prod", Name: "api-config"}, AssetType: "Secret"}},
		SecurityControls: []snapshot.SecurityControl{{Ref: snapshot.ObjectRef{Kind: "Namespace", Name: "prod"}, ControlType: "PodSecurityAdmission", Mode: "restricted"}},
	}
}
