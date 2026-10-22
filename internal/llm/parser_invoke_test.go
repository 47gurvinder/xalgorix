package llm

import "testing"

// Some providers emit the alternate <invoke name=…> vocabulary with missing or
// unbalanced quotes around the name while the parameter body stays well-formed
// and closes with </function>. The strict both-quotes form matched none of
// these, so they parsed as "no tool call" and drove the malformed-recovery
// ladder. These are the exact shapes observed in a production scan log.
func TestParseToolCalls_LooseInvokeName(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{
			name:     "unquoted invoke name",
			input:    "<invoke name=update_hypothesis>\n<parameter=hypothesis_id>H-237</parameter>\n<parameter=status>rejected</parameter>\n</function>",
			wantName: "update_hypothesis",
			wantKey:  "status",
			wantVal:  "rejected",
		},
		{
			name:     "opening quote, no closing quote",
			input:    "<invoke name=\"claim_next_hypothesis>\n<parameter=vuln_class>cloud-config</parameter>\n</function>",
			wantName: "claim_next_hypothesis",
			wantKey:  "vuln_class",
			wantVal:  "cloud-config",
		},
		{
			name:     "well-formed invoke still works",
			input:    "<invoke name=\"terminal_execute\">\n<parameter=command>id</parameter>\n</invoke>",
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "id",
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

// A batch of unquoted invokes closing with </function> yields one call each.
func TestParseToolCalls_LooseInvokeBatch(t *testing.T) {
	in := "<invoke name=\"claim_next_hypothesis>\n<parameter=vuln_class>cloud-config</parameter>\n</function>\n" +
		"<invoke name=\"claim_next_hypothesis>\n<parameter=vuln_class>cms-security</parameter>\n</function>"
	calls := ParseToolCalls(in)
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d (%+v)", len(calls), calls)
	}
	if calls[0].Args["vuln_class"] != "cloud-config" || calls[1].Args["vuln_class"] != "cms-security" {
		t.Fatalf("unexpected args: %+v", calls)
	}
}

// Prose mentioning the word "invoke" must not be misread as a tool call.
func TestParseToolCalls_LooseInvoke_NoFalsePositive(t *testing.T) {
	if calls := ParseToolCalls("You can invoke name resolution via DNS."); len(calls) != 0 {
		t.Fatalf("prose: expected 0 calls, got %d (%+v)", len(calls), calls)
	}
}
