package llm

import "testing"

// Some providers intermittently substitute ">" for "=" in the function-open
// tag — `<function>NAME>` instead of `<function=NAME>` — while the parameter
// body stays well-formed. Every other open-tag repair requires an "=", so
// these turns were misread as "no tool call" and classified malformed_tool_xml,
// adding a recovery round-trip each. These are the exact shapes observed in a
// production scan log.
func TestParseToolCalls_RepairsGtForEqFunctionOpen(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{
			name:     "gt-for-eq open, correct param body",
			input:    "<function>scan_source_sinks>\n<parameter=max_per_class>20</parameter>\n</function>",
			wantName: "scan_source_sinks",
			wantKey:  "max_per_class",
			wantVal:  "20",
		},
		{
			name:     "gt-for-eq open preceded by a stray close",
			input:    "</function>\n\n<function>check_agent>\n<parameter=agent_id>sub_1_123</parameter>\n</function>\n</function>",
			wantName: "check_agent",
			wantKey:  "agent_id",
			wantVal:  "sub_1_123",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := ParseToolCalls(tc.input)
			if len(calls) != 1 {
				t.Fatalf("expected 1 call, got %d (%+v)", len(calls), calls)
			}
			if calls[0].Name != tc.wantName {
				t.Fatalf("name = %q, want %q", calls[0].Name, tc.wantName)
			}
			if got := calls[0].Args[tc.wantKey]; got != tc.wantVal {
				t.Fatalf("arg %q = %q, want %q", tc.wantKey, got, tc.wantVal)
			}
		})
	}
}

// A function with no parameters, closed directly, still repairs.
func TestParseToolCalls_GtForEqOpen_NoParams(t *testing.T) {
	calls := ParseToolCalls("<function>list_agents>\n</function>")
	if len(calls) != 1 || calls[0].Name != "list_agents" {
		t.Fatalf("expected list_agents call, got %+v", calls)
	}
}

// Guards against over-eager rewriting:
//   - a correct <function=name> tag is untouched (idempotent),
//   - a parameter value containing ">" (e.g. a shell redirect) is NOT split,
//   - prose mentioning <function> with no identifier+param body yields no call.
func TestParseToolCalls_GtForEqOpen_NoFalsePositives(t *testing.T) {
	// Correct form still parses and keeps a ">"-bearing value intact.
	calls := ParseToolCalls("<function=terminal_execute>\n<parameter=command>echo hi > /tmp/f</parameter>\n</function>")
	if len(calls) != 1 || calls[0].Name != "terminal_execute" {
		t.Fatalf("correct form: expected terminal_execute, got %+v", calls)
	}
	if got := calls[0].Args["command"]; got != "echo hi > /tmp/f" {
		t.Fatalf("redirect value mangled: command = %q", got)
	}

	// Prose that merely contains the literal "<function>" is not a call.
	if calls := ParseToolCalls("the <function> keyword is reserved"); len(calls) != 0 {
		t.Fatalf("prose: expected 0 calls, got %d (%+v)", len(calls), calls)
	}
}
