package agent

import (
	"strings"

	"github.com/Autumn-27/norma/harness"
)

// Wrap-up / settlement prompt: when an agent is terminated because of [steps exhausted (MaxTurns)] or
// [timeout (run_seconds/MaxDuration)], the SDK's settlement phase injects this prompt,
// so the agent first writes back what it has identified but not yet stored, then outputs a summary, avoiding an abrupt end.
//
// Each agent's wrap-up prompt can be overridden in the backend on demand (stored in agents.wrapup_prompt); when blank the built-in
// default here is used. Only the [prompt body] is editable; which tools are disabled and how many turns the wrap-up itself is given are fixed code policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. worker reuses the historically hard-coded settleWrapUpPrompt
// (defined in worker.go); planner/mainagent each have their own; an unmatched one (a custom agent) uses the generic fallback.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: the built-in default turn budget for each agent's [own] wrap-up phase (overridable by a backend value >0).
// All given 10 turns, to ensure the wrap-up phase has enough steps to store things. An unmatched one uses genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "Your planning steps this round are about to run out — note that only [this round] is ending; the system will still wake you again as the situation changes to keep planning, so this is not the end of the task and you need not wrap up the whole plan here. Land the conclusions you have already thought through this round, so the round is not wasted, but also [do not force intents just to wrap up] (0 intents this round is still a perfectly normal result): (1) if you have judged an exploration direction that [should be issued now], submit it in one batch add_intent (do not hold back ones you have decided on); (2) for a goal already proven met by some finding/fact, call prove_goal to mark it met (do not miss any); (3) if you identified a serial exploitation chain that needs stepping, note it with TodoWrite so the next wake-up can continue issuing. When done, end the round directly, with no need to output summary text."

const mainAgentWrapUpDefault = "Your steps are about to run out and this interaction is ending. Do not start any new exploration/operation. In **a single plain-text sentence**, summarise the current progress, key conclusions and the suggested next step for the user."

const genericWrapUpDefault = "You are about to be terminated because the budget is exhausted. First write back results that are complete but not yet stored, then in **a single plain-text sentence** summarise what you did and what key conclusions you reached (this sentence is shown as the result of this run)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- Task-level timeout wrap-up prompts (see docs/task-level-timeout-and-wrap-up-design.md) ----------
//
// These are a [separate set] from the per-run wrap-up prompts: per-run is "your budget for this one run is used up"; task timeout is
// "the whole task is due and about to end". The meanings are often opposite (especially for the planner: per-run says "do not stop, keep planning",
// task timeout says "stop planning, it is due, make the final judgement"). Configured only for worker/planner.

// WrapupTaskTimeoutOverride / …TurnsOverride: the DB overrides for the task-timeout wrap-up prompt and turn count
// (wired to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The whole task has reached its timeout limit and is about to end** (not your budget for this run; the whole exploration is due). This is the last chance: (1) write back [everything] you have identified but not yet stored — new assets insert_assets, exploration conclusions/facts record_fact, confirmed vulnerabilities report_finding; (2) do not start any new command/probe; (3) **finally, in a single plain-text sentence**, summarise your key conclusions on this intent."

const plannerTaskTimeoutDefault = "**The whole task has reached its timeout limit and is about to end** (not this round, the whole task is terminating). Based on [all] current facts and findings, make one last goal judgement: for a goal proven met by evidence, call prove_goal to mark it met (do not miss any). **Do not generate any new intents** (an issued intent would no longer be executed now). Once judged, wrap up, with no need to output summary text."

// TaskTimeoutWrapupDefault returns an agent's built-in default task-timeout wrap-up prompt (for the backend placeholder/restore default).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // not configured (mainagent/chat) returns an empty string
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. An empty string means this agent has no task-timeout prompt
// (not worker/planner), in which case the caller should fall back to the per-run prompt.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // by default follow the per-run turn count
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run is clamped by the task deadline: a Timeout wrap-up = the task is due → the task-timeout prompt;
//     a MaxTurns wrap-up = steps ran out first inside the clamped window while the task still has a few minutes → falls back to the per-run prompt.
//   - clamped=false → the task is not due yet: both reasons use the per-run prompt (i.e. degrades to wrapupSettlement).
//
// leave it to the harness's PromptByReason to pick live by the [actual] reason at wrap-up, with no build-time mismatch.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (also the value for both reasons when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // the task is due
				harness.ReasonMaxTurns: perRun, // steps ran out first while the task still has time
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
