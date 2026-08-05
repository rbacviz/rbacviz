package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rbacviz/rbacviz/internal/app"
	"github.com/rbacviz/rbacviz/internal/apperr"
	graphmodel "github.com/rbacviz/rbacviz/internal/graph"
)

func newGraphCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	command := &cobra.Command{Use: "graph", Short: "Inspect and traverse the typed permission graph", Args: cobra.NoArgs}
	command.AddCommand(newGraphStatsCommand(streams, dependencies, state))
	command.AddCommand(newGraphNodesCommand(streams, dependencies, state))
	command.AddCommand(newGraphPathsCommand(streams, dependencies, state))
	return command
}

func newGraphStatsCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	return &cobra.Command{
		Use: "stats", Short: "Print typed graph node and edge counts", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			analyzer, err := loadGraphAnalyzer(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			return writeGraphStats(streams.Out, state.result.Config.Output, analyzer.Stats(), analyzer.Warnings())
		},
	}
}

func newGraphNodesCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var typeValues []string
	var namespace, kind, name, keyPrefix string
	var limit int
	command := &cobra.Command{
		Use: "nodes", Short: "List graph nodes and their portable selectors", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			types, err := graphmodel.ParseNodeTypes(typeValues)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.nodes.type", err.Error(), err)
			}
			if limit < 1 {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.nodes.limit", "--limit must be at least 1", nil)
			}
			analyzer, err := loadGraphAnalyzer(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			nodes := analyzer.Select(graphmodel.Selector{Types: types, Namespace: namespace, Kind: kind, Name: name, KeyPrefix: keyPrefix})
			truncated := len(nodes) > limit
			if truncated {
				nodes = nodes[:limit]
			}
			return writeGraphNodes(streams.Out, state.result.Config.Output, nodes, truncated)
		},
	}
	command.Flags().StringSliceVar(&typeValues, "type", nil, "node type filter (repeatable or comma-separated)")
	command.Flags().StringVar(&namespace, "node-namespace", "", "node namespace filter")
	command.Flags().StringVar(&kind, "kind", "", "Kubernetes kind filter")
	command.Flags().StringVar(&name, "name", "", "exact node name filter")
	command.Flags().StringVar(&keyPrefix, "key-prefix", "", "portable key prefix filter")
	command.Flags().IntVar(&limit, "limit", 200, "maximum nodes to print")
	return command
}

func newGraphPathsCommand(streams IOStreams, dependencies Dependencies, state *commandState) *cobra.Command {
	var from, to string
	var topK, maxDepth, maxExpanded int
	command := &cobra.Command{
		Use: "paths", Short: "Find bounded top-K loopless weighted graph paths", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.paths.endpoints", "--from and --to are required", nil)
			}
			if topK < 1 || topK > 100 {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.paths.k", "--k must be between 1 and 100", nil)
			}
			if maxDepth < 1 || maxDepth > 100 {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.paths.depth", "--max-depth must be between 1 and 100", nil)
			}
			if maxExpanded < 1 {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.paths.expanded", "--max-expanded must be at least 1", nil)
			}
			analyzer, err := loadGraphAnalyzer(command.Context(), dependencies, state)
			if err != nil {
				return err
			}
			fromNode, err := analyzer.Resolve(from)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.paths.from", err.Error(), err)
			}
			toNode, err := analyzer.Resolve(to)
			if err != nil {
				return apperr.New(apperr.KindInvalidInput, "cli.graph.paths.to", err.Error(), err)
			}
			result, err := analyzer.TopKPaths(command.Context(), fromNode.ID, toNode.ID, graphmodel.PathLimits{K: topK, MaxDepth: maxDepth, MaxExpanded: maxExpanded})
			if err != nil {
				return apperr.New(apperr.KindOperational, "cli.graph.paths.search", "graph path search failed", err)
			}
			return writeGraphPaths(streams.Out, state.result.Config.Output, result)
		},
	}
	command.Flags().StringVar(&from, "from", "", "source node ID or exact portable key")
	command.Flags().StringVar(&to, "to", "", "target node ID or exact portable key")
	command.Flags().IntVarP(&topK, "k", "k", 3, "number of paths (1-100)")
	command.Flags().IntVar(&maxDepth, "max-depth", 12, "maximum edges per candidate path")
	command.Flags().IntVar(&maxExpanded, "max-expanded", 50000, "maximum expanded path candidates")
	return command
}

func loadGraphAnalyzer(ctx context.Context, dependencies Dependencies, state *commandState) (*app.GraphAnalyzer, error) {
	value, err := loadAnalysisSnapshot(ctx, dependencies, state)
	if err != nil {
		return nil, err
	}
	analyzer, err := app.NewGraphAnalyzer(value)
	if err != nil {
		return nil, apperr.New(apperr.KindValidation, "cli.graph.build", "cannot build typed permission graph", err)
	}
	return analyzer, nil
}

func writeGraphStats(writer io.Writer, output string, stats graphmodel.Stats, warnings []graphmodel.Warning) error {
	if output == "json" {
		return writeGraphJSON(writer, struct {
			Stats    graphmodel.Stats     `json:"stats"`
			Warnings []graphmodel.Warning `json:"warnings"`
		}{stats, warnings})
	}
	if _, err := fmt.Fprintf(writer, "graph schema: %s\nnodes: %d\nedges: %d\nwarnings: %d\n", stats.SchemaVersion, stats.Nodes, stats.Edges, stats.Warnings); err != nil {
		return graphOutputError(err)
	}
	for _, item := range stats.NodesByType {
		if _, err := fmt.Fprintf(writer, "node type: %s %d\n", item.Type, item.Count); err != nil {
			return graphOutputError(err)
		}
	}
	for _, item := range stats.EdgesByType {
		if _, err := fmt.Fprintf(writer, "edge relation: %s %d\n", item.Relation, item.Count); err != nil {
			return graphOutputError(err)
		}
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(writer, "warning: %s: %s\n", warning.Code, warning.Message); err != nil {
			return graphOutputError(err)
		}
	}
	return nil
}

func writeGraphNodes(writer io.Writer, output string, nodes []graphmodel.Node, truncated bool) error {
	payload := struct {
		SchemaVersion string            `json:"schemaVersion"`
		Nodes         []graphmodel.Node `json:"nodes"`
		Truncated     bool              `json:"truncated"`
	}{graphmodel.SchemaVersion, nodes, truncated}
	if output == "json" {
		return writeGraphJSON(writer, payload)
	}
	if _, err := fmt.Fprintf(writer, "nodes: %d\ntruncated: %t\n", len(nodes), truncated); err != nil {
		return graphOutputError(err)
	}
	for _, node := range nodes {
		if _, err := fmt.Fprintf(writer, "- %s %s\n  id: %s\n", node.Type, node.Key, node.ID); err != nil {
			return graphOutputError(err)
		}
	}
	return nil
}

func writeGraphPaths(writer io.Writer, output string, result graphmodel.PathResult) error {
	if output == "json" {
		return writeGraphJSON(writer, result)
	}
	if _, err := fmt.Fprintf(writer, "from: %s\nto: %s\npaths: %d\nexpanded: %d\ntruncated: %t\n", result.From.Key, result.To.Key, len(result.Paths), result.Expanded, result.Truncated); err != nil {
		return graphOutputError(err)
	}
	for index, path := range result.Paths {
		if _, err := fmt.Fprintf(writer, "path %d: cost=%d id=%s\n", index+1, path.Cost, path.ID); err != nil {
			return graphOutputError(err)
		}
		for edgeIndex, edge := range path.Edges {
			if _, err := fmt.Fprintf(writer, "  %s --%s/%d--> %s\n", path.Nodes[edgeIndex].Key, edge.Relation, edge.Cost, path.Nodes[edgeIndex+1].Key); err != nil {
				return graphOutputError(err)
			}
		}
	}
	return nil
}

func writeGraphJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return graphOutputError(err)
	}
	return nil
}

func graphOutputError(err error) error {
	return apperr.New(apperr.KindOperational, "cli.graph.output", "cannot write graph output", err)
}
