package agent

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

// This file turns the "built-in tools" from pure code into an enumerable catalogue that the DB can override:
//   - BuiltinToolSeeds(): expands the three execution agents' built-in tool sets into seed records (key +
//     description + parameter schema + the agents bound by default), for the server to idempotently seed into the tools table at start-up.
//   - the ToolResolve hook: at runtime, applies the tools rows in the DB to the assembled tools ("filter by agent +
//     override description/schema + inject parameter defaults"). The key/handler stay at the code layer; the DB only changes "the prose and defaults".
// the handler (Call behaviour) always comes from code — the DB cannot change it, only the description the model sees and the default arguments.

// ToolSeed is a seedable snapshot of a built-in tool: key is CoreTool.Name() (hard-bound to the handler,
// read-only in the UI), Desc/Schema come from the tool definition in code, and Agents is which agents the code gives it to by default.
type ToolSeed struct {
	Key    string         // = CoreTool.Name(), the primary key, immutable
	Desc   string         // top-level description (overridable in the UI)
	Schema map[string]any // parameter JSON-Schema (structure read-only, description/default editable in the UI)
	Agents []string       // agent keys bound by default (worker/planner/mainagent)
}

// builtinToolsByAgent uses a "read-only shell" ToolSet (nil stores) to construct each execution agent's
// domain tool set. Tool constructors only stuff a closure into the Spec and do not dereference the store at construction time, so nil is safe:
// these tools are used here only to read Name()/Description()/InputSchema(), never to Call.
//
// It deliberately [excludes] the SDK's common tools actool.DefaultTools() (Read/Write/Edit/MultiEdit/LS/Glob/
// Grep/Bash): every agent always has them, there is no "bound to whom" choice, and their descriptions are mostly in Prompt()
// (this table only overrides Description(), which would cause a half-override and mislead). Not seeded → no DB row → ToolResolve
// passes them through unchanged, behaving as before. Only artex's own domain tools go into the table and are manageable.
func builtinToolsByAgent() map[string][]actool.CoreTool {
	ts := NewToolSet(nil, "")
	return map[string][]actool.CoreTool{
		"mainagent": ts.MainAgentTools(),
		"planner":   ts.PlannerTools(),
		"worker":    ts.WorkerTools(),
		// goals (the goal decomposer) is bound by default to set_goals + set_constraints: it relies on them to write the decomposed goals and
		// the extracted operational constraints into the database. It shares the same managed tools as mainagent, so the web side can change the description/schema and tick per agent.
		"goals": {ts.setGoals(), ts.setConstraints()},
		// auto is bound by default to the vulnerability-reporting + asset-management tools; other domain tools can be ticked on demand in the UI.
		// a new database is written by this seed; an old database is migrated by seedAutoDefaultBindings.
		"auto": {ts.addFinding(), ts.insertAssets(), ts.addCompanyScope(), ts.listAssets(), ts.listCompanies()},
		// pentest (the solo pentest agent) is bound by default to: query assets / insert assets / report vulnerabilities / query vulnerabilities / query companies.
		// a new database is written by this seed; an old database is migrated by seedPentestDefaultBindings.
		"pentest": {ts.listAssets(), ts.insertAssets(), ts.addFinding(), ts.listFindings(), ts.listCompanies()},
	}
}

// defaultUnbound: these system tools still go into the catalogue as usual (visible on the web side, can be ticked per agent by hand), but
// by default are [bound to no agent] — ToolResolve drops a tool with empty bindings for every agent, so it must be opted in explicitly.
// The reason they still remain in some agent's base tool set (e.g. goal_met in PlannerTools): one, so the seed can
// construct it and get its desc/schema; two, so that once a user binds it back it is in the base at runtime and ToolResolve can keep it.
//
// goal_met: bypasses per-goal prove_goal and declares [the whole task complete] from the global level directly; it carries a lot of weight and a risk of misjudgement, and duplicates
// "prove_goal marking the last goal → automatic finish", so it is given to no agent by default and bound by hand when needed.
var defaultUnbound = map[string]bool{"goal_met": true}

// BuiltinToolSeeds de-duplicates and merges each agent's built-in tool sets into a seed list: tools of the same name (such as list_assets,
// which several agents have) are merged into one with the union of their Agents; tools in defaultUnbound are forced to an empty binding.
func BuiltinToolSeeds() []ToolSeed {
	byAgent := builtinToolsByAgent()
	order := []string{"mainagent", "goals", "planner", "worker", "auto", "pentest"}

	type acc struct {
		tool   actool.CoreTool
		agents []string
	}
	m := map[string]*acc{}
	var keys []string
	for _, ak := range order {
		for _, t := range byAgent[ak] {
			a, ok := m[t.Name()]
			if !ok {
				a = &acc{tool: t}
				m[t.Name()] = a
				keys = append(keys, t.Name())
			}
			a.agents = append(a.agents, ak)
		}
	}

	out := make([]ToolSeed, 0, len(keys))
	for _, k := range keys {
		a := m[k]
		agents := a.agents
		if defaultUnbound[k] {
			agents = []string{} // in the catalogue, bindable by hand, but given to no agent by default (stored as [] rather than null, consistent with other tools)
		}
		out = append(out, ToolSeed{
			Key:    k,
			Desc:   a.tool.Description(),
			Schema: a.tool.InputSchema(),
			Agents: agents,
		})
	}
	return out
}

// ToolResolve, if set, post-processes an agent's fully-assembled tool list against
// the DB tools table: it drops tools not bound to this agent (or globally disabled)
// and wraps the rest so the model sees the DB-overridden description/schema and
// default arguments get injected. Tools with no matching DB row (MCP/skill/host tools like
// traffic) pass through untouched. nil = tools unchanged. Wired in server/assembly.go.
var ToolResolve func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool

// DecorateTool wraps t so Description()/InputSchema() report the DB overrides and
// Call() injects scalar parameter defaults (from schema's "default" props) whenever
// the model omitted them. Name/Prompt/permission/scheduler flags delegate to t, so
// the tool's identity and handler are unchanged. Empty desc/schema fall back to t's.
func DecorateTool(t actool.CoreTool, desc string, schema map[string]any) actool.CoreTool {
	if desc == "" {
		desc = t.Description()
	}
	if len(schema) == 0 {
		schema = t.InputSchema()
	}
	return &overriddenTool{CoreTool: t, desc: desc, schema: schema}
}

// overriddenTool is a CoreTool decorator: it embeds the original (so all behavioral
// methods — Prompt/IsReadOnly/IsConcurrencySafe/CheckPermissions/Name — delegate)
// and overrides only the model-facing description/schema plus default injection.
type overriddenTool struct {
	actool.CoreTool
	desc   string
	schema map[string]any
}

func (o *overriddenTool) Description() string         { return o.desc }
func (o *overriddenTool) InputSchema() map[string]any { return o.schema }

func (o *overriddenTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	return o.CoreTool.Call(ctx, injectDefaults(in, o.schema), tc)
}

// injectDefaults fills scalar parameter defaults declared in the (possibly edited)
// schema into the input JSON whenever the model omitted the field or left it empty/
// null. Structure (names/types/required) is untouched — only default values are merged in.
func injectDefaults(in json.RawMessage, schema map[string]any) json.RawMessage {
	defs := scalarDefaults(schema)
	if len(defs) == 0 {
		return in
	}
	m := map[string]json.RawMessage{}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return in // non-object input: don't touch it
		}
	}
	changed := false
	for k, dv := range defs {
		if cur, ok := m[k]; !ok || isEmptyJSON(cur) {
			m[k] = dv
			changed = true
		}
	}
	if !changed {
		return in
	}
	b, err := json.Marshal(m)
	if err != nil {
		return in
	}
	return b
}

// scalarDefaults extracts properties[k]["default"] for scalar params (string/
// integer/number/boolean). Array/object defaults are skipped: merging them is
// ambiguous and not worth the surprise.
func scalarDefaults(schema map[string]any) map[string]json.RawMessage {
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		return nil
	}
	out := map[string]json.RawMessage{}
	for name, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		dv, ok := p["default"]
		if !ok || dv == nil {
			continue
		}
		switch p["type"] {
		case "string", "integer", "number", "boolean":
			if b, err := json.Marshal(dv); err == nil {
				out[name] = b
			}
		}
	}
	return out
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := string(raw)
	return s == "null" || s == `""`
}
