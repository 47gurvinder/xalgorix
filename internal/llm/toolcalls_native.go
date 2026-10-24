package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// This file implements the optional native (OpenAI-style) tool-calling channel.
//
// The default protocol is XML embedded in the assistant's text (see parser.go).
// That requires the model to have been trained on the XML dialect; models that
// were not — small ones especially — answer in prose and never call a tool.
//
// The native channel instead sends tool definitions as a JSON-schema `tools`
// array and reads calls back from `tool_calls`. On llama.cpp this additionally
// enables constrained decoding: the server derives a GBNF grammar from the
// schema, so a malformed call becomes impossible rather than merely repaired.
//
// Everything here is inert unless the operator opts in via
// XALGORIX_NATIVE_TOOL_CALLS and the endpoint speaks the OpenAI protocol.

// ToolDefinition is the provider-neutral description of one tool offered to the
// model through the native channel.
type ToolDefinition struct {
	Name        string
	Description string
	Parameters  []ToolParameter
}

// ToolParameter describes a single tool argument.
type ToolParameter struct {
	Name        string
	Description string
	Required    bool
}

// MessageToolCall is an assistant-side tool call as it must be replayed in the
// conversation history, so the following role:"tool" results line up by id.
type MessageToolCall struct {
	ID       string              `json:"id"`
	Type     string              `json:"type"`
	Function MessageToolFunction `json:"function"`
}

// MessageToolFunction carries the tool name and its JSON-encoded arguments.
type MessageToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// chatTool is one entry of the request `tools` array.
type chatTool struct {
	Type     string       `json:"type"`
	Function chatToolFunc `json:"function"`
}

type chatToolFunc struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  chatToolParams `json:"parameters"`
}

type chatToolParams struct {
	Type       string                      `json:"type"`
	Properties map[string]chatToolProperty `json:"properties"`
	Required   []string                    `json:"required,omitempty"`
}

type chatToolProperty struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// chatToolCall is one entry of a response `tool_calls` array. Per the OpenAI
// spec `arguments` is a JSON *string*, but some servers send a raw object; the
// jsonString decoder accepts both and preserves the exact bytes either way.
type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string     `json:"name"`
		Arguments jsonString `json:"arguments"`
	} `json:"function"`
}

// jsonString decodes a JSON value that may be a string (the spec) or a raw
// object/array (non-conforming servers), keeping the original encoding.
type jsonString string

// UnmarshalJSON implements json.Unmarshaler for jsonString.
func (j *jsonString) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*j = jsonString(s)
		return nil
	}
	*j = jsonString(b)
	return nil
}

// buildChatTools converts provider-neutral definitions into the wire format of
// the chat-completions `tools` array.
//
// Every parameter is declared as type "string": xalgorix executors take
// map[string]string, and structured arguments (task lists, header maps) are
// already carried as JSON-encoded strings on the XML path too, so the two
// channels stay interchangeable. The output is sorted by name so the request
// body is byte-stable across calls and provider prefix caching keeps working.
func buildChatTools(defs []ToolDefinition) []chatTool {
	if len(defs) == 0 {
		return nil
	}
	out := make([]chatTool, 0, len(defs))
	for _, d := range defs {
		props := make(map[string]chatToolProperty, len(d.Parameters))
		required := make([]string, 0, len(d.Parameters))
		for _, p := range d.Parameters {
			props[p.Name] = chatToolProperty{Type: "string", Description: p.Description}
			if p.Required {
				required = append(required, p.Name)
			}
		}
		sort.Strings(required)
		out = append(out, chatTool{
			Type: "function",
			Function: chatToolFunc{
				Name:        d.Name,
				Description: d.Description,
				Parameters: chatToolParams{
					Type:       "object",
					Properties: props,
					Required:   required,
				},
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Function.Name < out[j].Function.Name })
	return out
}

// argumentsToArgs decodes a tool call's `arguments` JSON into the
// map[string]string the executors expect.
//
// Conversion rules:
//   - string        -> as-is
//   - number / bool -> compact literal ("30", "true")
//   - null          -> key omitted (an optional argument not provided)
//   - object/array  -> compact JSON text, preserving structured arguments
//
// An empty payload or JSON null yields an empty map. Anything that is not a
// JSON object at the top level is an error; the caller keeps the call and
// surfaces the error to the model instead of silently dropping it.
func argumentsToArgs(raw string) (map[string]string, error) {
	args := make(map[string]string)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return args, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return args, fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	for k, v := range obj {
		if string(bytes.TrimSpace(v)) == "null" {
			continue
		}
		s, err := rawValueToString(v)
		if err != nil {
			return args, fmt.Errorf("argument %q: %w", k, err)
		}
		args[k] = s
	}
	return args, nil
}

// rawValueToString renders one JSON value as the string an executor expects:
// strings verbatim, everything else as compact JSON.
func rawValueToString(v json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s, nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// parseOpenAIToolCalls converts the wire-level tool_calls of a response into
// ToolCalls. A malformed `arguments` payload does not discard the call: it is
// preserved with ArgumentError so the agent can hand the model a corrective
// tool result rather than losing the turn.
func parseOpenAIToolCalls(raw []chatToolCall) []ToolCall {
	if len(raw) == 0 {
		return nil
	}
	calls := make([]ToolCall, 0, len(raw))
	for _, c := range raw {
		name := strings.TrimSpace(c.Function.Name)
		if name == "" {
			continue
		}
		args, err := argumentsToArgs(string(c.Function.Arguments))
		tc := ToolCall{
			ID:           c.ID,
			Name:         name,
			Args:         args,
			RawArguments: string(c.Function.Arguments),
		}
		if err != nil {
			tc.ArgumentError = err.Error()
		}
		calls = append(calls, tc)
	}
	return calls
}

// MessageToolCallsFrom renders ToolCalls back into the assistant-turn shape
// that must be replayed in the history for the provider to accept the
// role:"tool" results that follow.
func MessageToolCallsFrom(calls []ToolCall) []MessageToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]MessageToolCall, 0, len(calls))
	for _, c := range calls {
		args := c.RawArguments
		if args == "" {
			encoded, err := json.Marshal(c.Args)
			if err != nil {
				encoded = []byte("{}")
			}
			args = string(encoded)
		}
		out = append(out, MessageToolCall{
			ID:       c.ID,
			Type:     "function",
			Function: MessageToolFunction{Name: c.Name, Arguments: args},
		})
	}
	return out
}

// EnsureToolCallIDs assigns a deterministic synthetic id to any call the server
// returned without one (llama-server does this), so every replayed tool result
// can carry a matching tool_call_id.
func EnsureToolCallIDs(calls []ToolCall, prefix string) []ToolCall {
	for i := range calls {
		if calls[i].ID == "" {
			calls[i].ID = fmt.Sprintf("%s_%d", prefix, i)
		}
	}
	return calls
}

// NormalizeNativeToolHistory rewrites a request snapshot so it satisfies the
// OpenAI tool protocol: each assistant turn carrying tool calls is immediately
// followed by one role:"tool" result per call id, and orphaned tool results are
// demoted to user turns.
//
// The agent loop has several early exits (blocked calls, nudges, pruning) that
// can leave a call without its result. Rather than spreading fragile repair
// logic across every call site, this pure function is applied to the request
// snapshot only — the agent's own history is never mutated.
//
// When the history contains no native tool calls it is returned unchanged, so
// the legacy XML path keeps byte-identical requests.
func NormalizeNativeToolHistory(msgs []Message) []Message {
	hasNative := false
	for _, m := range msgs {
		if len(m.ToolCalls) > 0 {
			hasNative = true
			break
		}
	}
	if !hasNative {
		return msgs
	}

	// Tool results already present, keyed by call id.
	byID := make(map[string]Message, len(msgs))
	for _, m := range msgs {
		if m.Role == "tool" && m.ToolCallID != "" {
			byID[m.ToolCallID] = m
		}
	}
	// Call ids that some assistant turn claims.
	claimed := make(map[string]bool, len(byID))
	for _, m := range msgs {
		for _, tc := range m.ToolCalls {
			claimed[tc.ID] = true
		}
	}

	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		switch {
		case m.Role == "tool":
			// Re-emitted under its assistant turn (or demoted below if orphaned).
			continue
		case len(m.ToolCalls) == 0:
			out = append(out, m)
		default:
			out = append(out, m)
			for _, tc := range m.ToolCalls {
				if r, ok := byID[tc.ID]; ok {
					out = append(out, r)
					continue
				}
				out = append(out, Message{
					Role:       "tool",
					ToolCallID: tc.ID,
					Content:    "no result recorded (call was blocked, skipped or truncated)",
				})
			}
		}
	}
	// Orphaned results (their assistant turn was pruned away) become user
	// turns. Iterating the original slice keeps the order deterministic.
	for _, m := range msgs {
		if m.Role == "tool" && !claimed[m.ToolCallID] {
			out = append(out, Message{Role: "user", Content: "(tool result) " + m.Content})
		}
	}
	return out
}
