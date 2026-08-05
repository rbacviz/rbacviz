package graph

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	defaultMaxDepth    = 12
	defaultMaxExpanded = 50000
	defaultTopK        = 3
)

// Traverse returns reachable nodes in stable breadth-first order.
func (graph *Graph) Traverse(ctx context.Context, start string, direction Direction, limits TraversalLimits) (TraversalResult, error) {
	startIndex, found := graph.byID[start]
	if !found {
		return TraversalResult{}, fmt.Errorf("start node %q was not found", start)
	}
	if direction == "" {
		direction = DirectionOutgoing
	}
	if direction != DirectionOutgoing && direction != DirectionIncoming && direction != DirectionBoth {
		return TraversalResult{}, fmt.Errorf("unknown traversal direction %q", direction)
	}
	limits = normalizeTraversalLimits(limits)
	type item struct{ node, depth int }
	queue := []item{{node: startIndex}}
	seen := map[int]struct{}{startIndex: {}}
	result := TraversalResult{SchemaVersion: SchemaVersion, Start: start, Nodes: []Node{graph.nodes[startIndex]}}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return TraversalResult{}, err
		}
		current := queue[0]
		queue = queue[1:]
		if current.depth >= limits.MaxDepth {
			if len(graph.neighbors(current.node, direction)) > 0 {
				result.Truncated = true
			}
			continue
		}
		if result.Expanded >= limits.MaxExpanded {
			result.Truncated = true
			break
		}
		result.Expanded++
		neighbors := graph.neighbors(current.node, direction)
		for _, neighbor := range neighbors {
			if _, exists := seen[neighbor]; exists {
				continue
			}
			seen[neighbor] = struct{}{}
			queue = append(queue, item{node: neighbor, depth: current.depth + 1})
			result.Nodes = append(result.Nodes, graph.nodes[neighbor])
		}
	}
	return result, nil
}

func (graph *Graph) neighbors(node int, direction Direction) []int {
	seen := make(map[int]struct{})
	if direction == DirectionOutgoing || direction == DirectionBoth {
		for _, edgeIndex := range graph.out[node] {
			seen[graph.byID[graph.edges[edgeIndex].To]] = struct{}{}
		}
	}
	if direction == DirectionIncoming || direction == DirectionBoth {
		for _, edgeIndex := range graph.in[node] {
			seen[graph.byID[graph.edges[edgeIndex].From]] = struct{}{}
		}
	}
	result := make([]int, 0, len(seen))
	for index := range seen {
		result = append(result, index)
	}
	sort.Slice(result, func(i, j int) bool { return graph.nodes[result[i]].ID < graph.nodes[result[j]].ID })
	return result
}

// TopKPaths performs bounded uniform-cost enumeration of loopless directed
// paths. Non-negative costs and total heap ordering make the first K terminal
// candidates the deterministic top-K paths within the configured bounds.
func (graph *Graph) TopKPaths(ctx context.Context, from, to string, limits PathLimits) (PathResult, error) {
	fromIndex, fromFound := graph.byID[from]
	toIndex, toFound := graph.byID[to]
	if !fromFound {
		return PathResult{}, fmt.Errorf("source node %q was not found", from)
	}
	if !toFound {
		return PathResult{}, fmt.Errorf("target node %q was not found", to)
	}
	limits = normalizePathLimits(limits)
	result := PathResult{SchemaVersion: SchemaVersion, From: graph.nodes[fromIndex], To: graph.nodes[toIndex], Paths: []Path{}}
	queue := &pathHeap{}
	heap.Init(queue)
	heap.Push(queue, &pathCandidate{node: fromIndex, edge: -1, rank: sha256.Sum256([]byte(graph.nodes[fromIndex].ID))})
	for queue.Len() > 0 && len(result.Paths) < limits.K {
		if err := ctx.Err(); err != nil {
			return PathResult{}, err
		}
		if result.Expanded >= limits.MaxExpanded {
			result.Truncated = true
			break
		}
		candidate := heap.Pop(queue).(*pathCandidate)
		current := candidate.node
		if current == toIndex {
			result.Paths = append(result.Paths, graph.materializePath(candidate))
			continue
		}
		if candidate.depth >= limits.MaxDepth {
			if len(graph.out[current]) > 0 {
				result.Truncated = true
			}
			continue
		}
		result.Expanded++
		for _, edgeIndex := range graph.out[current] {
			edge := graph.edges[edgeIndex]
			next := graph.byID[edge.To]
			if candidateContainsNode(candidate, next) {
				continue
			}
			heap.Push(queue, &pathCandidate{parent: candidate, node: next, edge: edgeIndex, depth: candidate.depth + 1, cost: candidate.cost + uint64(edge.Cost), rank: nextPathRank(candidate.rank, edge.ID)})
		}
	}
	if queue.Len() > 0 && len(result.Paths) < limits.K {
		result.Truncated = true
	}
	return result, nil
}

func (graph *Graph) materializePath(candidate *pathCandidate) Path {
	nodes := make([]Node, candidate.depth+1)
	edges := make([]Edge, candidate.depth)
	current := candidate
	for index := candidate.depth; index >= 0; index-- {
		nodes[index] = graph.nodes[current.node]
		if index > 0 {
			edges[index-1] = graph.edges[current.edge]
			current = current.parent
		}
	}
	return Path{ID: "path-" + hex.EncodeToString(candidate.rank[:12]), Cost: candidate.cost, Nodes: nodes, Edges: edges}
}

type pathCandidate struct {
	parent *pathCandidate
	node   int
	edge   int
	depth  int
	cost   uint64
	rank   [sha256.Size]byte
}

func candidateContainsNode(candidate *pathCandidate, wanted int) bool {
	for current := candidate; current != nil; current = current.parent {
		if current.node == wanted {
			return true
		}
	}
	return false
}

func nextPathRank(previous [sha256.Size]byte, edgeID string) [sha256.Size]byte {
	value := make([]byte, 0, len(previous)+len(edgeID)+1)
	value = append(value, previous[:]...)
	value = append(value, 0)
	value = append(value, edgeID...)
	return sha256.Sum256(value)
}

type pathHeap []*pathCandidate

func (values pathHeap) Len() int { return len(values) }
func (values pathHeap) Less(i, j int) bool {
	if values[i].cost != values[j].cost {
		return values[i].cost < values[j].cost
	}
	if values[i].depth != values[j].depth {
		return values[i].depth < values[j].depth
	}
	return bytes.Compare(values[i].rank[:], values[j].rank[:]) < 0
}
func (values pathHeap) Swap(i, j int)   { values[i], values[j] = values[j], values[i] }
func (values *pathHeap) Push(value any) { *values = append(*values, value.(*pathCandidate)) }
func (values *pathHeap) Pop() any {
	old := *values
	last := old[len(old)-1]
	*values = old[:len(old)-1]
	return last
}

func normalizeTraversalLimits(value TraversalLimits) TraversalLimits {
	if value.MaxDepth <= 0 {
		value.MaxDepth = defaultMaxDepth
	}
	if value.MaxExpanded <= 0 {
		value.MaxExpanded = defaultMaxExpanded
	}
	return value
}

func normalizePathLimits(value PathLimits) PathLimits {
	if value.K <= 0 {
		value.K = defaultTopK
	}
	if value.MaxDepth <= 0 {
		value.MaxDepth = defaultMaxDepth
	}
	if value.MaxExpanded <= 0 {
		value.MaxExpanded = defaultMaxExpanded
	}
	return value
}

// ParseNodeTypes validates case-insensitive CLI values.
func ParseNodeTypes(values []string) ([]NodeType, error) {
	result := make([]NodeType, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			candidate := NodeType(strings.ToUpper(strings.TrimSpace(part)))
			if candidate == "" {
				continue
			}
			if !validNodeType(candidate) {
				return nil, fmt.Errorf("unknown node type %q", part)
			}
			result = append(result, candidate)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	result = dedupeNodeTypes(result)
	return result, nil
}

func validNodeType(value NodeType) bool {
	switch value {
	case NodeIdentity, NodeServiceAccount, NodeBinding, NodeRole, NodeClusterRole, NodeCapability, NodeResourceSelector, NodeWorkload, NodePod, NodeSecret, NodeNode, NodePersistentVolume, NodeNamespace, NodeAsset, NodeSecurityControl, NodeAttackTechnique, NodePrivilegeTarget:
		return true
	default:
		return false
	}
}

func dedupeNodeTypes(values []NodeType) []NodeType {
	if len(values) == 0 {
		return []NodeType{}
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
