package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Graph is immutable after construction. Numeric indexes are internal only;
// public results always use portable stable IDs.
type Graph struct {
	nodes    []Node
	edges    []Edge
	warnings []Warning
	byID     map[string]int
	byKey    map[string][]int
	out      [][]int
	in       [][]int
	byType   map[NodeType][]int
}

// New validates, canonicalizes, and indexes a typed multigraph.
func New(nodes []Node, edges []Edge, warnings []Warning) (*Graph, error) {
	nodes = append([]Node(nil), nodes...)
	edges = append([]Edge(nil), edges...)
	warnings = append([]Warning(nil), warnings...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	sort.Slice(warnings, func(i, j int) bool {
		return warnings[i].Code+"\x00"+warnings[i].Message < warnings[j].Code+"\x00"+warnings[j].Message
	})

	graph := &Graph{
		nodes: nodes, edges: edges, warnings: warnings,
		byID: make(map[string]int, len(nodes)), byKey: make(map[string][]int),
		out: make([][]int, len(nodes)), in: make([][]int, len(nodes)),
		byType: make(map[NodeType][]int),
	}
	for index, node := range nodes {
		if node.ID == "" || node.Type == "" || node.Key == "" {
			return nil, fmt.Errorf("node at index %d is missing id, type, or key", index)
		}
		if _, exists := graph.byID[node.ID]; exists {
			return nil, fmt.Errorf("duplicate node id %q", node.ID)
		}
		graph.byID[node.ID] = index
		graph.byKey[node.Key] = append(graph.byKey[node.Key], index)
		graph.byType[node.Type] = append(graph.byType[node.Type], index)
	}
	seenEdges := make(map[string]struct{}, len(edges))
	for index, edge := range edges {
		if edge.ID == "" || edge.Relation == "" {
			return nil, fmt.Errorf("edge at index %d is missing id or relation", index)
		}
		if _, exists := seenEdges[edge.ID]; exists {
			return nil, fmt.Errorf("duplicate edge id %q", edge.ID)
		}
		seenEdges[edge.ID] = struct{}{}
		from, fromOK := graph.byID[edge.From]
		to, toOK := graph.byID[edge.To]
		if !fromOK || !toOK {
			return nil, fmt.Errorf("edge %q references missing endpoint", edge.ID)
		}
		if len(edge.Evidence) == 0 {
			return nil, fmt.Errorf("edge %q has no evidence", edge.ID)
		}
		graph.out[from] = append(graph.out[from], index)
		graph.in[to] = append(graph.in[to], index)
	}
	return graph, nil
}

// Nodes returns a copy in stable ID order.
func (graph *Graph) Nodes() []Node { return append([]Node(nil), graph.nodes...) }

// Edges returns a copy in stable ID order.
func (graph *Graph) Edges() []Edge { return append([]Edge(nil), graph.edges...) }

// Warnings returns construction warnings in stable order.
func (graph *Graph) Warnings() []Warning { return append([]Warning(nil), graph.warnings...) }

// Node resolves one stable ID.
func (graph *Graph) Node(id string) (Node, bool) {
	index, found := graph.byID[id]
	if !found {
		return Node{}, false
	}
	return graph.nodes[index], true
}

// Resolve accepts either an exact node ID or an exact portable key.
func (graph *Graph) Resolve(value string) (Node, error) {
	if node, found := graph.Node(value); found {
		return node, nil
	}
	indexes := graph.byKey[value]
	if len(indexes) == 0 {
		return Node{}, fmt.Errorf("graph node %q was not found", value)
	}
	if len(indexes) > 1 {
		return Node{}, fmt.Errorf("graph key %q is ambiguous", value)
	}
	return graph.nodes[indexes[0]], nil
}

// Select performs an indexed type scan and deterministic filtering.
func (graph *Graph) Select(selector Selector) []Node {
	indexes := make([]int, 0)
	if len(selector.Types) == 0 {
		for index := range graph.nodes {
			indexes = append(indexes, index)
		}
	} else {
		seen := make(map[int]struct{})
		for _, nodeType := range selector.Types {
			for _, index := range graph.byType[nodeType] {
				seen[index] = struct{}{}
			}
		}
		for index := range seen {
			indexes = append(indexes, index)
		}
		sort.Ints(indexes)
	}
	result := make([]Node, 0, len(indexes))
	for _, index := range indexes {
		node := graph.nodes[index]
		if selector.Namespace != "" && node.Namespace != selector.Namespace {
			continue
		}
		if selector.Kind != "" && !strings.EqualFold(node.Kind, selector.Kind) {
			continue
		}
		if selector.Name != "" && node.Name != selector.Name {
			continue
		}
		if selector.KeyPrefix != "" && !strings.HasPrefix(node.Key, selector.KeyPrefix) {
			continue
		}
		result = append(result, node)
	}
	return result
}

// Stats returns stable counts without exposing internal indexes.
func (graph *Graph) Stats() Stats {
	types := make(map[NodeType]int)
	relations := make(map[Relation]int)
	for _, node := range graph.nodes {
		types[node.Type]++
	}
	for _, edge := range graph.edges {
		relations[edge.Relation]++
	}
	typeKeys := make([]string, 0, len(types))
	for key := range types {
		typeKeys = append(typeKeys, string(key))
	}
	sort.Strings(typeKeys)
	relationKeys := make([]string, 0, len(relations))
	for key := range relations {
		relationKeys = append(relationKeys, string(key))
	}
	sort.Strings(relationKeys)
	result := Stats{SchemaVersion: SchemaVersion, Nodes: len(graph.nodes), Edges: len(graph.edges), Warnings: len(graph.warnings)}
	for _, key := range typeKeys {
		result.NodesByType = append(result.NodesByType, TypeCount{Type: NodeType(key), Count: types[NodeType(key)]})
	}
	for _, key := range relationKeys {
		result.EdgesByType = append(result.EdgesByType, RelationCount{Relation: Relation(key), Count: relations[Relation(key)]})
	}
	return result
}

func stableID(prefix string, parts ...string) string {
	digest := sha256.Sum256([]byte(prefix + "\x00" + strings.Join(parts, "\x00")))
	return prefix + "-" + hex.EncodeToString(digest[:12])
}
