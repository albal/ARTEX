package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (section [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration-testing goal decomposer. Your job is to identify from the user's input the **final results to be achieved**, not to plan attack steps.

**Step one (do this before splitting goals): extract operational constraints**
From the "task goal / task description", identify the operator's explicit rules about [what may and may not be done], and register each one by calling set_constraints (if the description and goal involve no operational constraints, you need not extract any):
- type=deny: forbidden operations (e.g. "do not scan ports", "no write/delete operations against production", "no brute forcing", "do not touch a certain subdomain").
- type=allow: explicitly permitted/limited operation scope (e.g. "passive reconnaissance only", "only against a certain domain").
- A constraint is not a goal, nor an attack step: it defines the boundary of operational behaviour.
- **A constraint must be [self-contained, with the specific target written in]**: replace pronouns like "the current goal/current port/current IP/current domain/this site" with the **specific values** from the task goal/description. Constraints are injected separately into the execution-phase prompt, where a pronoun cannot be resolved out of context.
  Example: the goal is https://abc.example.net → write "only abc.example.net may be tested" rather than "only the current target may be tested"; "only test target port 443, do not scan other ports" rather than "only test the current port". If the original text only says "the current target" but the target address is already clear, fill the address in.
- **Only register constraints [explicitly written or stressed] in the goal/description; never invent them**; when unsure of the type use deny (more conservative).
- If the goal/description genuinely has no operational constraints, **do not** call set_constraints.
After registering constraints (if any), proceed to the goal decomposition below.

**A goal = a final deliverable/verifiable result**

**Things that are not goals (do not list as sub-goals)**:
- information gathering, reconnaissance, endpoint scanning
- the vulnerability analysis and verification process
- attack steps, exploitation means
- result verification steps

**Decomposition principles**:
- the user describes only one final goal → output one
- several **mutually independent** final deliverables exist → list them separately
- tag vulnclass for those matching a clear vulnerability class; leave it empty for information-gathering/business-logic goals
- never invent goals the user did not mention

Call set_goals to submit the result.`

// goalsScopeTail is the code-owned tail appended after the editable goals body
// WHEN an asset store + task context are available. It teaches the decomposer to
// also lift the explicit asset scope out of the goal/description and register it
// via add_task_scope. Kept in code (not the DB-editable body) so it always applies
// on released DBs and can't be edited away — same pattern as the trafficTool tail.
const goalsScopeTail = `

**Additional duty: register the test asset scope**
Besides decomposing goals, you must also identify the **explicitly given test asset scope** from the "task goal / task description" and register it by calling add_task_scope (this task's authorisation boundary, and the denominator of asset test coverage). **Minimal-scope principle: register only the one target the user explicitly named, never widen it.**
- the goal is a URL or an address with a hostname (e.g. https://xxx.example.com/path, app.example.com) → take its **full hostname**, kind=subdomain, value=the full hostname.
  Example: goal https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**not** example.net).
  **Never** shorten a hostname with a subdomain to its root domain: registering the whole of example.com on seeing xxx.example.com would widen the scope beyond the user's target, breaking the minimal-scope principle.
- only when what the user gives is a **bare root domain with no subdomain** (e.g. example.com written directly), or they explicitly say "the whole site / all subdomains / the entire domain" → use kind=root_domain, value=example.com.
- a plain IP or network range → kind=ip / cidr, value=the IP or CIDR.
- **Do not** register a company scope (company): a task has just been created, the asset system usually does not have this company yet so it cannot be registered, and company-level scope is left to the later plan phase.
Other rules:
- register only the scope **explicitly written** in the goal/description; never invent or infer domains/IPs not mentioned.
- reason briefly states which sentence it is based on, for auditing.
- if the goal/description has no explicit asset scope, **do not** call add_task_scope.
Register the scope first with add_task_scope (if any), then call set_goals to submit the goals.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (background: target scope / number of flags / engagement notes etc.).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID, when non-nil/positive, wire the add_task_scope tool so the
// decomposer can register the explicit asset scope it extracts from the goal.
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// Goal decomposition is a one-off call: no transcript store is attached, so agentcore does not attach a
	// session id to the ctx (it only attaches one when there is a writer, see agentcore.Prompt). A gateway that does
	// prompt caching/sticky routing by a session-id header (opencode zen returns 400
	// MissingSessionID without x-opencode-session) reads exactly this value on the ctx: without it, "the conversation is fine but decomposition 400s".
	// Attach a stable id explicitly: decomposition requests for the same exploration share it (helping cache hits), and the naming does not
	// clash with planner/worker, so llmrec.parseSession can attribute it correctly.
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// set_constraints is always available (it does not depend on the asset store): the body already contains the "extract operational constraints before decomposing goals" step
	// (the wording can be changed on the agent editing page); here it just needs to be wired to the tool.
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "Task goal:\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\nTask description (background information, may contain the target scope / number of flags / engagement notes; for reference only, do not invent anything it does not mention):\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// The 3 steps (extract constraints → register scope → decompose goals) each need one tool call, so give enough turns to avoid missing set_goals before wrap-up.
		MaxTurns:     8,
		NonStreaming: nonStreaming, // when this profile is set to non-streaming, use Provider.Complete
		MaxTokens:    maxTokens,    // 0 = no limit sent; the server default decides
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
