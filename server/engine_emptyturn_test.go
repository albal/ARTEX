package server

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// recognising an idle turn (thinking only, no body and no tool) and continuing it, see steerHooks.Stop.

func assistantThinking(text string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: text, Signature: "sig"},
	}}
}

func TestIsThinkingOnlyTurn(t *testing.T) {
	toolUse := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockThinking, Thinking: "scan the ports first"},
		{Type: llm.BlockToolUse, ID: "t1", Name: "run_nuclei"},
	}}
	cases := []struct {
		name string
		msgs []llm.Message
		want bool
	}{
		{"thinking only", []llm.Message{llm.UserText("start"), assistantThinking("let me think")}, true},
		{"thinking+tool", []llm.Message{llm.UserText("start"), toolUse}, false},
		{"thinking+body", []llm.Message{assistantThinking("let me think"), {
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("conclusion")},
		}}, false},
		{"body is whitespace only", []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "x"}, llm.TextBlock("  \n ")},
		}}, true},
		{"a completely empty assistant turn", []llm.Message{{Role: llm.RoleAssistant}}, true},
		// a tool result is the user role, so the decision must look back to the assistant before it, not misjudge the nearest one.
		{"the last one is a tool result", []llm.Message{toolUse, {
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: "t1"}},
		}}, false},
		{"no assistant message", []llm.Message{llm.UserText("start")}, false},
		{"empty history", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isThinkingOnlyTurn(c.msgs); got != c.want {
				t.Fatalf("isThinkingOnlyTurn = %v, want %v", got, c.want)
			}
		})
	}
}

// fakeHooks is a programmable inner HookRunner, used to verify that steerHooks respects inner's decision.
type fakeHooks struct {
	prevent  bool
	blocking []string
	msg      string
}

func (f fakeHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (f fakeHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (f fakeHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return f.prevent, f.blocking, f.msg
}

func TestSteerHooksStopNudgesEmptyTurn(t *testing.T) {
	empty := []llm.Message{assistantThinking("I should enumerate the subdomains first")}

	t.Run("an idle turn injects a continuation instruction", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges, label: "worker-1 · #1"}
		prevent, blocking, _ := h.Stop(context.Background(), empty)
		if prevent {
			t.Fatal("an idle turn should not hard-stop")
		}
		if len(blocking) != 1 || blocking[0] != emptyTurnNudge {
			t.Fatalf("blocking = %v, want [emptyTurnNudge]", blocking)
		}
	})

	t.Run("do not intervene when there is body or a tool", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		normal := []llm.Message{{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("scan complete, no open ports found")},
		}}
		if _, blocking, _ := h.Stop(context.Background(), normal); blocking != nil {
			t.Fatalf("a normal finish was misjudged as idle: %v", blocking)
		}
		if n := h.nudges.Load(); n != 0 {
			t.Fatalf("should not count when not intervening, got %d", n)
		}
	})

	t.Run("let it finish after reaching the cap", func(t *testing.T) {
		const limit = 5 // the user set "empty-response retry count" to 5
		h := steerHooks{nudges: &atomic.Int64{}, limit: limit}
		for i := 1; i <= limit; i++ {
			if _, blocking, _ := h.Stop(context.Background(), empty); len(blocking) != 1 {
				t.Fatalf("round %d should still be within quota, blocking = %v", i, blocking)
			}
		}
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("still injecting beyond the cap: %v", blocking)
		}
	})

	// "empty-response retry count" set to -1 = turn this layer off, and emptyTurnNudgeLimit resolves to 0.
	t.Run("do not intervene when configured off", func(t *testing.T) {
		h := steerHooks{nudges: &atomic.Int64{}, limit: 0}
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("still injecting when off: %v", blocking)
		}
	})

	t.Run("do not add on top when inner decides a hard stop", func(t *testing.T) {
		h := steerHooks{inner: fakeHooks{prevent: true, msg: "guard refused the finish"}, nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		prevent, blocking, msg := h.Stop(context.Background(), empty)
		if !prevent || msg != "guard refused the finish" || blocking != nil {
			t.Fatalf("inner's hard stop was overwritten: prevent=%v blocking=%v msg=%q", prevent, blocking, msg)
		}
		if n := h.nudges.Load(); n != 0 {
			t.Fatalf("should not consume quota when yielding to inner, got %d", n)
		}
	})

	t.Run("do not add on top when inner already wants a continuation", func(t *testing.T) {
		h := steerHooks{inner: fakeHooks{blocking: []string{"guard's continuation reason"}}, nudges: &atomic.Int64{}, limit: defaultEmptyTurnNudges}
		_, blocking, _ := h.Stop(context.Background(), empty)
		if len(blocking) != 1 || blocking[0] != "guard's continuation reason" {
			t.Fatalf("inner's continuation message was overwritten: %v", blocking)
		}
	})

	t.Run("behaviour unchanged when no counter is installed", func(t *testing.T) {
		h := steerHooks{limit: defaultEmptyTurnNudges} // e.g. a future call site forgot to pass nudges
		if _, blocking, _ := h.Stop(context.Background(), empty); blocking != nil {
			t.Fatalf("should not inject with no counter: %v", blocking)
		}
	})
}
