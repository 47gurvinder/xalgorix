package llm

import "testing"

// Regression for the production waste where the model wrote a function
// OPEN as a parameter tag (<parameter=NAME> for <function=NAME>), because both
// use the <tag=value> syntax. The whole call was then unparseable, classified
// malformed_tool_xml, and the turn discarded + retried with a full context
// resend — a dominant token sink. These are the exact shapes from the prod log.
func TestParseToolCalls_RecoversMisTaggedFunctionOpen(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantName  string
		wantParam string
		wantVal   string
	}{
		{
			name:      "ledger update mis-tagged (exact prod shape)",
			input:     "<parameter=update_hypothesis>\n<parameter=hypothesis_id>H-97</parameter>\n<parameter=status>rejected</parameter>",
			wantName:  "update_hypothesis",
			wantParam: "hypothesis_id",
			wantVal:   "H-97",
		},
		{
			name:      "mis-tagged with trailing stray close",
			input:     "<parameter=terminal_execute>\n<parameter=command>id</parameter>\n</function>",
			wantName:  "terminal_execute",
			wantParam: "command",
			wantVal:   "id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := ParseToolCalls(tc.input)
			if len(calls) != 1 {
				t.Fatalf("expected 1 recovered call, got %d: %+v", len(calls), calls)
			}
			if calls[0].Name != tc.wantName {
				t.Fatalf("name = %q, want %q", calls[0].Name, tc.wantName)
			}
			if got := calls[0].Args[tc.wantParam]; got != tc.wantVal {
				t.Fatalf("param %s = %q, want %q (args=%+v)", tc.wantParam, got, tc.wantVal, calls[0].Args)
			}
		})
	}
}

// The repair must never rewrite a legitimate parameter whose value happens to
// contain markup: a well-formed call is left exactly as-is (guarded by the
// no-well-formed-call precondition), so there are no false positives.
func TestParseToolCalls_MisTagRepairLeavesWellFormedCallsIntact(t *testing.T) {
	// A real call whose parameter VALUE contains a <parameter ...> string.
	in := `<function=terminal_execute><parameter=command>grep "<parameter=x>" file</parameter></function>`
	calls := ParseToolCalls(in)
	if len(calls) != 1 || calls[0].Name != "terminal_execute" {
		t.Fatalf("well-formed call altered: %+v", calls)
	}
	if calls[0].Args["command"] != `grep "<parameter=x>" file` {
		t.Fatalf("parameter value corrupted: %q", calls[0].Args["command"])
	}

	// Two legitimate params back-to-back (each with a value + close) must NOT be
	// misread as a mis-tagged function open.
	in2 := `<function=report_vulnerability><parameter=title>SQLi</parameter><parameter=severity>high</parameter></function>`
	calls2 := ParseToolCalls(in2)
	if len(calls2) != 1 || calls2[0].Name != "report_vulnerability" || calls2[0].Args["severity"] != "high" {
		t.Fatalf("adjacent params misread: %+v", calls2)
	}
}
