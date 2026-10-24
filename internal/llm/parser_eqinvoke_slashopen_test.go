package llm

import "testing"

// Two malformed open-tag shapes observed being DISCARDED in a production scan
// log (the model fighting the tool-call protocol), both with well-formed bodies:
//  1. "<invoke=NAME>"      — Claude invoke vocabulary with "=" instead of name="…"
//  2. "</function=NAME>"   — a function OPEN tag mangled with a leading slash
//
// Each previously failed to parse, so a real probe/ledger op was thrown away and
// the turn drove the malformed-recovery ladder. Both must now recover to one call.
func TestParseToolCalls_RecoversEqInvokeAndSlashOpen(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{
			name:     "equals-style invoke open",
			input:    "<invoke=read_ledger>\n<parameter=filter>schedulable</parameter>\n</function>",
			wantName: "read_ledger",
			wantKey:  "filter",
			wantVal:  "schedulable",
		},
		{
			name:     "leading-slash function open (real probe)",
			input:    "</function=terminal_execute>\n<parameter=command>id</parameter>\n</function>",
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "id",
		},
		{
			name:     "equals-style invoke, quoted name",
			input:    "<invoke=\"send_request\">\n<parameter=method>GET</parameter>\n</function>",
			wantName: "send_request",
			wantKey:  "method",
			wantVal:  "GET",
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

// Safety: a well-formed call must be untouched, and the legitimate "</function>"
// close tag must never be rewritten into an open (it carries no "=NAME").
func TestParseToolCalls_EqInvokeSlashOpen_NoFalsePositive(t *testing.T) {
	// Well-formed call with a normal close — still exactly one call.
	ok := ParseToolCalls("<function=terminal_execute>\n<parameter=command>whoami</parameter>\n</function>")
	if len(ok) != 1 || ok[0].Name != "terminal_execute" || ok[0].Args["command"] != "whoami" {
		t.Fatalf("well-formed call altered: %+v", ok)
	}
	// Two well-formed calls back to back: the real "</function>" closes must not
	// be misread as mangled opens.
	two := ParseToolCalls("<function=a>\n<parameter=x>1</parameter>\n</function>\n<function=b>\n<parameter=y>2</parameter>\n</function>")
	if len(two) != 2 {
		t.Fatalf("expected 2 calls, got %d (%+v)", len(two), two)
	}
	// Prose mentioning the tokens is not a call.
	if calls := ParseToolCalls("Set invoke=true in the config and the function=handler mapping."); len(calls) != 0 {
		t.Fatalf("prose: expected 0 calls, got %d (%+v)", len(calls), calls)
	}
}
