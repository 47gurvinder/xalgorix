package tools

import (
	"strings"
	"testing"
)

// The lean-schema transform must DROP example/workflow spans in lean mode and
// KEEP them (markers stripped) in full mode — while never touching core text,
// tool names, or parameters. This is the coverage-safety contract: the
// documented, reachable tool set is identical in both modes; only illustrative
// examples differ.
func TestLeanSchemaRendering(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{
		Name:        "demo_tool",
		Description: "Core: does the thing. Always provide the target.\n\n⟦ex⟧EXAMPLE:\n  demo_tool target=https://x\n  (lots of worked illustration)⟦/ex⟧",
		Parameters: []Parameter{
			{Name: "target", Description: "The target URL. ⟦ex⟧e.g. https://example.com/api⟦/ex⟧", Required: true},
		},
	})

	full := r.SchemaXML()
	if !strings.Contains(full, "Core: does the thing") {
		t.Fatal("full: core description must be present")
	}
	if !strings.Contains(full, "worked illustration") {
		t.Fatal("full: example text must be kept")
	}
	if strings.Contains(full, "⟦ex⟧") || strings.Contains(full, "⟦/ex⟧") {
		t.Fatal("full: sentinel markers must be stripped")
	}
	if !strings.Contains(full, `<parameter name="target"`) || !strings.Contains(full, "The target URL.") {
		t.Fatal("full: parameter + its core description must be present")
	}

	r.SetLeanSchema(true)
	lean := r.SchemaXML()
	// Core text, tool name, and parameter are all preserved.
	if !strings.Contains(lean, "Core: does the thing") {
		t.Fatal("lean: core description must be preserved")
	}
	if !strings.Contains(lean, `<tool name="demo_tool"`) {
		t.Fatal("lean: tool must still be documented")
	}
	if !strings.Contains(lean, `<parameter name="target"`) || !strings.Contains(lean, "The target URL.") {
		t.Fatal("lean: parameter + its core description must be preserved")
	}
	// Example spans are gone.
	if strings.Contains(lean, "worked illustration") || strings.Contains(lean, "example.com/api") {
		t.Fatal("lean: example spans must be dropped")
	}
	if strings.Contains(lean, "⟦") {
		t.Fatal("lean: no sentinel residue")
	}
	if len(lean) >= len(full) {
		t.Fatalf("lean (%d) must be smaller than full (%d)", len(lean), len(full))
	}
}
