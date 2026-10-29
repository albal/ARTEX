package agent

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	tx              *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window          int                                    // context window in tokens (for compaction)
	windowFn        func() int                             // optional dynamic task-chain minimum
	maxTurns        int                                    // max agent turns per run (0 = unlimited)
	proxyAddr       string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert     string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch       WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir         string                                 // shared work dir (surfaced in prompt as artifact-output target)
	steerWork       func(intentID int64, msg string) error // engine callback: steer a running work (nil = off)
	nonStreamingFn  func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn    func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn     func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
}

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (m *MainAgent) SetNoaEnabled(fn func() bool) { m.noaEnabledFn = fn }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (m *MainAgent) SetNonStreaming(fn func() bool) { m.nonStreamingFn = fn }

func (m *MainAgent) nonStreaming() bool { return m.nonStreamingFn != nil && m.nonStreamingFn() }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (m *MainAgent) SetMaxTokens(fn func() int) { m.maxTokensFn = fn }

func (m *MainAgent) maxTokens() int {
	if m.maxTokensFn == nil {
		return 0
	}
	return m.maxTokensFn()
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

func (m *MainAgent) SetCompactionWindowResolver(fn func() int) { m.windowFn = fn }

func (m *MainAgent) compactionWindow() int {
	if m.windowFn != nil {
		return m.windowFn()
	}
	return m.window
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// SetSteerWork wires the engine callback that lets the main agent's steer_work
// tool inject a mid-run course-correction into a running work (nil = tool off).
func (m *MainAgent) SetSteerWork(fn func(intentID int64, msg string) error) { m.steerWork = fn }

// mainAgentDefaultTmpl is the built-in EDITABLE body (section [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the
// artifact-output convention tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the "main agent" of an authorised penetration testing system, the interface to the human operator. You do not explore yourself, nor continuously generate intents on your own (that is the planner's job). Your duties:

1. Observe: use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer the person's questions about current progress.
2. Steer (turn the person's intent into system actions):
   - The person wants to "change direction / emphasise a class of finding / focus on an area" → use add_hint to write a hint (the planner reads it next time).
   - The person wants to "test a specific target right now" → use add_intent to inject a high-priority intent directly (priority 8-10). The system automatically pulls a completed task back into the running state, lets a worker claim and execute this intent, and returns to the completed state once done.
     **When all task goals are already met** (goals in graph_overview are all met): before issuing, judge whether this intent implies a "new result to be achieved". If it does, restate the goal you suspect to the person in one sentence and **ask whether to register it as a formal goal**: if yes → use set_goals to register it (the task then enters normal planning and the planner drives it forward on its own); if not / they just want a quick look → only add_intent to issue this one, and once the worker finishes the task returns to the completed state (it does not continue on its own). If this intent is clearly just a one-off check with no implied new goal, just add_intent; there is no need to ask every time.
   - The person wants to "steer a running intent (work) in real time (stop doing X, focus on Y)" → use steer_work (does not interrupt and does not lose existing progress; it takes effect before the worker's next action); first use get_worker_output to see what it is doing. If the whole direction is wrong, use add_intent to issue a new intent instead.
   - The person wants to "add a new final goal to achieve" → use set_goals to add the goal. The system writes the goal into the task graph and **automatically pulls completed/paused tasks back into the running state to continue** (the planner then re-judges whether it is met), with no need for a manual resume.
   - The person wants to "add/change test constraints (permit/forbid a class of operation, e.g. 'only test the current port', 'no brute forcing', 'passive reconnaissance only')" → use set_constraints to register them (type=allow to permit / type=deny to forbid). Constraints are injected into the planner/worker prompts on the next planning round to frame the exploration boundary; they can also be added, changed or removed under "Constraint management" in the overview.
3. Reply in plain language, concisely, saying what you did.

Current task goal: {{.Goal}}

Do not fabricate findings; answer only from the real data returned by the tools.`

func mainAgentSystem(goal, dataDir, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	tsx := NewToolSet(ts, "human")
	tsx.SetFindingRecorder(m.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.SetNotify(notify)         // general wake-up (write operations with no dedicated callback go through it, debounced)
	tsx.SetResumeTask(resume)     // a set_goals new goal → pulls completed/paused tasks back to running
	tsx.SetNotifyGoal(notifyGoal) // a set_goals new goal → records a "the person added a goal: …" trigger for the planner
	tsx.SetNotifyHint(notifyHint) // an add_hint new hint → records a "the person added N strategic hints: …" trigger for the planner
	tsx.steerWork = m.steerWork   // enable steer_work tool (nil = unavailable)
	// domain tools + the base default tool set (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	// when the asset coverage feature is off, add_task_scope/list_untested_assets are removed (not put into the prompt).
	base := append(tsx.DropCoverageTools(tsx.MainAgentTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	// this task's working directory <workDir>/tasks/<taskID>, created first.
	mainDir := ensureRunDir(m.workDir, taskID, 0)
	ctx = intercept.WithReviewWorkingDirectory(ctx, mainDir)
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir, mainDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // goes through the recording proxy to leave a trail; loads the proxy CA to verify the HTTPS certificate re-signed by the MITM
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is a separate egress proxy (http/https/socks5), unrelated to the MITM proxy that records traffic; empty means direct.
		EnableWebSearch:       m.webSearch.Enabled,
		WebSearchBackend:      m.webSearch.Backend,
		BraveSearchAPIKey:     m.webSearch.BraveKey,
		TavilySearchAPIKey:    m.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: m.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  m.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   m.webSearch.DeepSeekModel,
		WebSearchProxy:        m.webSearch.Proxy,
		BashEnv:               proxyEnv(m.proxyAddr, m.proxyCACert), // Bash sub-commands go through the proxy and trust the CA by default
		WorkingDir:            mainDir,                              // this task's working directory <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(mainDir),
		MaxTurns:              m.maxTurns,                             // 0 = unlimited (configurable in agent management)
		Compaction:            compactionConfig(m.compactionWindow()), // long chats stay within the window
		Todos:                 actool.NewTodoStore(),                  // session-scoped temporary todos (TodoWrite), purely for planning, discarded on exit
		// budget (steps) reached → the SDK runs wrap-up: it outputs a one-line progress summary to the user. The prompt and wrap-up turn count are editable in the backend (default 10 turns).
		Settlement:   wrapupSettlement("mainagent", nil),
		NonStreaming: m.nonStreaming(), // when this profile is set to non-streaming, use Provider.Complete
		MaxTokens:    m.maxTokens(),    // 0 = no limit sent; the server default decides
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per segment
		opts.Transcript = m.tx
		// Segment 0 keeps the legacy "exp%d-main" name so existing transcripts still
		// load; each new session (seg>=1) gets its own file for a clean context.
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
		if mainSeg > 0 {
			opts.SessionID = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
		}
	}
	// Experimental: when on, noa takes over context compaction (archives kept under <workDir>/noa/<SessionID>, persistent).
	// the session id follows the same rule as the transcript (segment-aware), so archiving and restoration line up.
	noaSession := fmt.Sprintf("exp%d-main", ts.ID())
	if mainSeg > 0 {
		noaSession = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
	}
	enableNoa(&opts, m.noaEnabledFn, m.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}
