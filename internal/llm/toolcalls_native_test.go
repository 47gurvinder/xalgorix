package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// newOpenAITestClient builds a client pinned to an OpenAI-style endpoint so the
// native tool-calling branch is the one under test.
func newOpenAITestClient(rt roundTripFunc) *Client {
	return NewClient(
		&config.Config{
			LLM:           "openai/gpt-4o",
			APIBase:       "https://api.openai.com/v1",
			APIKey:        "sk-test",
			LLMMaxRetries: 1,
		},
		WithHTTPClient(&http.Client{Transport: rt}),
	)
}

func TestChatWithUsageToolCallsSendsToolsAndParsesCalls(t *testing.T) {
	var gotBody map[string]any
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &gotBody); err != nil {
			return nil, err
		}
		return jsonResponse(200, `{
			"choices":[{"message":{"content":"","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"terminal_execute","arguments":"{\"command\":\"id\"}"}}
			]}}],
			"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}
		}`), nil
	})
	c := newOpenAITestClient(rt)

	defs := []ToolDefinition{{
		Name:        "terminal_execute",
		Description: "run a command",
		Parameters:  []ToolParameter{{Name: "command", Description: "shell command", Required: true}},
	}}

	content, calls, usage, err := c.ChatWithUsageToolCalls([]Message{{Role: "user", Content: "run id"}}, defs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "" {
		t.Fatalf("content = %q, want empty", content)
	}
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1: %+v", len(calls), calls)
	}
	if calls[0].Name != "terminal_execute" || calls[0].Args["command"] != "id" || calls[0].ID != "call_1" {
		t.Fatalf("call = %+v", calls[0])
	}
	if usage == nil || usage.PromptTokens != 10 {
		t.Fatalf("usage = %+v", usage)
	}

	tools, ok := gotBody["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("request body has no tools array: %v", gotBody["tools"])
	}
	tool := tools[0].(map[string]any)
	if tool["type"] != "function" {
		t.Fatalf("tool type = %v", tool["type"])
	}
	fn := tool["function"].(map[string]any)
	if fn["name"] != "terminal_execute" {
		t.Fatalf("tool name = %v", fn["name"])
	}
	params := fn["parameters"].(map[string]any)
	if params["type"] != "object" {
		t.Fatalf("parameters.type = %v", params["type"])
	}
	props := params["properties"].(map[string]any)
	if _, ok := props["command"]; !ok {
		t.Fatalf("parameters.properties missing command: %v", props)
	}
	req := params["required"].([]any)
	if len(req) != 1 || req[0] != "command" {
		t.Fatalf("required = %v", params["required"])
	}
}

func TestChatWithUsageOmitsToolsWhenUnused(t *testing.T) {
	var gotBody map[string]any
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &gotBody); err != nil {
			return nil, err
		}
		return jsonResponse(200, `{"choices":[{"message":{"content":"hi"}}]}`), nil
	})
	c := newOpenAITestClient(rt)

	if _, _, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v, ok := gotBody["tools"]; ok {
		t.Fatalf("the legacy path must not send tools, got %v", v)
	}
	msgs := gotBody["messages"].([]any)
	for _, m := range msgs {
		msg := m.(map[string]any)
		if _, ok := msg["tool_calls"]; ok {
			t.Fatalf("legacy message must not carry tool_calls: %v", msg)
		}
		if _, ok := msg["tool_call_id"]; ok {
			t.Fatalf("legacy message must not carry tool_call_id: %v", msg)
		}
	}
}

func TestNativeToolCallingSupportedOpenAI(t *testing.T) {
	c := newOpenAITestClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, `{}`), nil
	}))
	if !c.NativeToolCallingSupported() {
		t.Fatal("an OpenAI-compatible endpoint must report native tool-calling support")
	}
}

func TestNativeToolCallingSupportedRejectsAnthropic(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:     "anthropic/claude-sonnet-4",
		APIBase: "https://api.anthropic.com",
		APIKey:  "k",
	})
	if c.NativeToolCallingSupported() {
		t.Fatal("an Anthropic endpoint must not report native tool-calling support")
	}
}

func TestArgumentsToArgs(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    map[string]string
		wantErr bool
	}{
		{name: "empty string", raw: "", want: map[string]string{}},
		{name: "empty object", raw: "{}", want: map[string]string{}},
		{name: "null payload", raw: "null", want: map[string]string{}},
		{name: "plain string", raw: `{"command":"id"}`, want: map[string]string{"command": "id"}},
		{name: "escapes and unicode", raw: `{"q":"a\"b\nü"}`, want: map[string]string{"q": "a\"b\nü"}},
		{name: "integer", raw: `{"rate":30}`, want: map[string]string{"rate": "30"}},
		{name: "float", raw: `{"ratio":0.75}`, want: map[string]string{"ratio": "0.75"}},
		{name: "bool", raw: `{"verbose":true}`, want: map[string]string{"verbose": "true"}},
		{name: "null value is omitted", raw: `{"a":"x","b":null}`, want: map[string]string{"a": "x"}},
		{name: "nested object stays json", raw: `{"headers":{"Accept": "text/html"}}`, want: map[string]string{"headers": `{"Accept":"text/html"}`}},
		{name: "array stays json", raw: `{"tasks":["a","b"]}`, want: map[string]string{"tasks": `["a","b"]`}},
		{name: "invalid json", raw: `{not json}`, wantErr: true},
		{name: "top level array", raw: `[1,2]`, wantErr: true},
		{name: "top level string", raw: `"hello"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := argumentsToArgs(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (args=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("args = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseOpenAIToolCalls(t *testing.T) {
	raw := []chatToolCall{
		{ID: "call_1", Type: "function"},
		{ID: "call_2", Type: "function"},
	}
	raw[0].Function.Name = "terminal_execute"
	raw[0].Function.Arguments = `{"command":"id"}`
	raw[1].Function.Name = "add_note"
	raw[1].Function.Arguments = `{"text":"hi"}`

	got := parseOpenAIToolCalls(raw)
	if len(got) != 2 {
		t.Fatalf("got %d calls, want 2", len(got))
	}
	if got[0].Name != "terminal_execute" || got[0].Args["command"] != "id" || got[0].ID != "call_1" {
		t.Fatalf("first call wrong: %+v", got[0])
	}
	if got[0].RawArguments != `{"command":"id"}` {
		t.Fatalf("RawArguments = %q", got[0].RawArguments)
	}
	if got[1].Name != "add_note" || got[1].Args["text"] != "hi" {
		t.Fatalf("second call wrong: %+v", got[1])
	}
}

func TestParseOpenAIToolCallsMalformedArgumentsKept(t *testing.T) {
	raw := make([]chatToolCall, 1)
	raw[0].Function.Name = "terminal_execute"
	raw[0].Function.Arguments = `{broken`

	got := parseOpenAIToolCalls(raw)
	if len(got) != 1 {
		t.Fatalf("a malformed arguments payload must keep the call, got %d", len(got))
	}
	if got[0].ArgumentError == "" {
		t.Fatal("expected ArgumentError to be set")
	}
}

func TestParseOpenAIToolCallsSkipsNameless(t *testing.T) {
	raw := make([]chatToolCall, 1)
	raw[0].Function.Arguments = `{}`
	if got := parseOpenAIToolCalls(raw); len(got) != 0 {
		t.Fatalf("nameless call should be dropped, got %+v", got)
	}
}

func TestParseOpenAIToolCallsObjectArguments(t *testing.T) {
	// Some servers send arguments as a raw object instead of a JSON string.
	var call chatToolCall
	if err := json.Unmarshal([]byte(`{"id":"c1","type":"function","function":{"name":"t","arguments":{"command":"id"}}}`), &call); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := parseOpenAIToolCalls([]chatToolCall{call})
	if len(got) != 1 || got[0].Args["command"] != "id" {
		t.Fatalf("object-form arguments not decoded: %+v", got)
	}
}

func TestBuildChatTools(t *testing.T) {
	defs := []ToolDefinition{
		{Name: "zeta", Description: "last", Parameters: []ToolParameter{{Name: "b", Required: true}, {Name: "a"}}},
		{Name: "alpha", Description: "first"},
	}
	tools := buildChatTools(defs)
	if len(tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(tools))
	}
	if tools[0].Function.Name != "alpha" || tools[1].Function.Name != "zeta" {
		t.Fatalf("tools not sorted by name: %s, %s", tools[0].Function.Name, tools[1].Function.Name)
	}
	p := tools[1].Function.Parameters
	if p.Type != "object" {
		t.Fatalf("parameters type = %q", p.Type)
	}
	if len(p.Properties) != 2 || p.Properties["a"].Type != "string" {
		t.Fatalf("properties wrong: %+v", p.Properties)
	}
	if len(p.Required) != 1 || p.Required[0] != "b" {
		t.Fatalf("required = %v, want [b]", p.Required)
	}
}

func TestBuildChatToolsEmpty(t *testing.T) {
	if got := buildChatTools(nil); got != nil {
		t.Fatalf("nil definitions should yield nil tools, got %v", got)
	}
}

func TestEnsureToolCallIDs(t *testing.T) {
	calls := []ToolCall{{Name: "a"}, {Name: "b", ID: "keep"}}
	got := EnsureToolCallIDs(calls, "call_3")
	if got[0].ID != "call_3_0" {
		t.Fatalf("generated id = %q", got[0].ID)
	}
	if got[1].ID != "keep" {
		t.Fatalf("existing id was overwritten: %q", got[1].ID)
	}
}

func TestMessageToolCallsFrom(t *testing.T) {
	calls := []ToolCall{
		{ID: "c1", Name: "run", Args: map[string]string{"command": "id"}},
		{ID: "c2", Name: "raw", RawArguments: `{"x":1}`, Args: map[string]string{"x": "1"}},
	}
	got := MessageToolCallsFrom(calls)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Type != "function" || got[0].Function.Name != "run" || got[0].Function.Arguments != `{"command":"id"}` {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Function.Arguments != `{"x":1}` {
		t.Fatalf("RawArguments not preferred: %q", got[1].Function.Arguments)
	}
}

func TestNormalizeNativeToolHistoryNoNative(t *testing.T) {
	in := []Message{{Role: "user", Content: "hi"}, {Role: "assistant", Content: "hello"}}
	out := NormalizeNativeToolHistory(in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("legacy history must pass through unchanged:\ngot  %+v\nwant %+v", out, in)
	}
}

func TestNormalizeNativeToolHistoryCompletePair(t *testing.T) {
	in := []Message{
		{Role: "user", Content: "go"},
		{Role: "assistant", Content: "", ToolCalls: []MessageToolCall{{ID: "c1", Type: "function"}}},
		{Role: "tool", ToolCallID: "c1", Content: "done"},
	}
	out := NormalizeNativeToolHistory(in)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("a complete pair must be preserved:\ngot  %+v\nwant %+v", out, in)
	}
}

func TestNormalizeNativeToolHistorySynthesizesMissingResult(t *testing.T) {
	in := []Message{
		{Role: "assistant", Content: "", ToolCalls: []MessageToolCall{{ID: "c1"}, {ID: "c2"}}},
		{Role: "tool", ToolCallID: "c1", Content: "ok"},
	}
	out := NormalizeNativeToolHistory(in)
	if len(out) != 3 {
		t.Fatalf("got %d messages, want 3: %+v", len(out), out)
	}
	if out[1].Role != "tool" || out[1].ToolCallID != "c1" || out[1].Content != "ok" {
		t.Fatalf("existing result misplaced: %+v", out[1])
	}
	if out[2].Role != "tool" || out[2].ToolCallID != "c2" {
		t.Fatalf("missing result not synthesized: %+v", out[2])
	}
}

func TestNormalizeNativeToolHistoryDemotesOrphan(t *testing.T) {
	in := []Message{
		{Role: "tool", ToolCallID: "gone", Content: "stale"},
		{Role: "user", Content: "next"},
	}
	out := NormalizeNativeToolHistory(in)
	// No assistant turn carries tool calls, so this is not a native history at
	// all and must pass through untouched.
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("non-native history changed: %+v", out)
	}

	in2 := []Message{
		{Role: "assistant", Content: "", ToolCalls: []MessageToolCall{{ID: "c1"}}},
		{Role: "tool", ToolCallID: "c1", Content: "ok"},
		{Role: "tool", ToolCallID: "gone", Content: "stale"},
	}
	out2 := NormalizeNativeToolHistory(in2)
	for _, m := range out2 {
		if m.Role == "tool" && m.ToolCallID == "gone" {
			t.Fatalf("orphaned tool result was not demoted: %+v", out2)
		}
	}
}
