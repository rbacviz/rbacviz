// Command render-screenshots captures documentation images from the real TUI renderer.
package main

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/rbacviz/rbacviz/internal/snapshot"
	"github.com/rbacviz/rbacviz/internal/tui"
)

func main() {
	var input, output string
	flag.StringVar(&input, "snapshot", "examples/risk-token-minter.json", "canonical snapshot")
	flag.StringVar(&output, "output", "docs/assets", "screenshot output directory")
	flag.Parse()
	value, err := snapshot.Load(input)
	if err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(output, 0o750); err != nil {
		fatal(err)
	}
	for _, capture := range []struct {
		name string
		view tui.View
	}{{name: "tui-overview.svg", view: tui.ViewOverview}, {name: "tui-findings.svg", view: tui.ViewFindings}} {
		frame, err := tui.RenderSnapshot(context.Background(), value, 140, 34, capture.view)
		if err != nil {
			fatal(err)
		}
		// #nosec G306 -- these are intentionally public documentation assets.
		if err := os.WriteFile(filepath.Join(output, capture.name), renderSVG(ansi.Strip(frame), 140, 34), 0o644); err != nil {
			fatal(err)
		}
	}
}

func renderSVG(frame string, columns, rows int) []byte {
	const cellWidth, lineHeight, padding = 8.4, 18, 20
	width := float64(columns)*cellWidth + padding*2
	height := rows*lineHeight + padding*2
	var output strings.Builder
	fmt.Fprintf(&output, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%d" viewBox="0 0 %.0f %d" role="img" aria-label="rbacviz terminal UI screenshot">`, width, height, width, height)
	output.WriteString("\n<metadata>Generated from the real rbacviz TUI renderer using examples/risk-token-minter.json.</metadata>\n")
	fmt.Fprintf(&output, `<rect width="100%%" height="100%%" rx="12" fill="#111827"/>`)
	output.WriteByte('\n')
	for index, line := range strings.Split(frame, "\n") {
		if index >= rows {
			break
		}
		var escaped strings.Builder
		_ = xml.EscapeText(&escaped, []byte(line))
		fmt.Fprintf(&output, `<text x="%d" y="%d" fill="#d1d5db" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="14" xml:space="preserve">%s</text>`, padding, padding+(index+1)*lineHeight-4, escaped.String())
		output.WriteByte('\n')
	}
	output.WriteString("</svg>\n")
	return []byte(output.String())
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "render-screenshots:", err)
	os.Exit(1)
}
