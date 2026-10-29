package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**Vulnerability numbering convention**: finding_id is the standalone vulnerability record ID; finding_node_id is the exploration node ID. The id from list_findings / list_task_findings / node_detail / get_task_node_detail stays as the exploration node ID; read the standalone number from the finding_id in the same response. get_finding_traffic / bind_finding_traffic use the standalone finding_id. The finding_id parameter of the old update_finding_report still takes finding_node_id. Do not use the number on the first line of report_finding for evidence tools, and do not guess other numbers after a numbering error."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default the reporter agent checks and binds traffic before writing the report. The reporter keeps the verification commands, key output, and the real traffic IDs already in hand and their purpose in evidence, for the reporter agent to cross-check against the execution record; there is no need to look up extra packets for binding. Explicit immediate binding is also supported: traffic_refs or evidence_hint_id can submit verified references, the latter reading the structured references of a given hint in this task; if either is invalid the whole report fails. TCP/no-packet cases do not need these optional parameters. The returned finding_id and finding_node_id are the standalone record and the exploration node respectively."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing over a confirmed vulnerability, keep the IDs, purpose, notes and order of the verified traffic in the corresponding hint's traffic_refs (a single one at the top level, a batch in the matching hints element), and state in text which specific vulnerability it proves. The caller must not hand over only text and discard existing traffic references. Unverified candidates must not be passed on as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic evidence handover (optional)**: automatic binding is by default done by the reporter agent after the vulnerability is stored and before the report is written. The reporter should keep the verification commands, key output, and the real traffic IDs already in hand and their purpose in evidence, carrying intent_id within a task so the reporter agent can trace it; there is no need to look up extra packets for binding. When Auto / Planner report on someone's behalf, do not discard the executor's existing references. add_hint / add_task_hint can hand over via traffic_refs; explicit immediate binding is still supported through report_finding's traffic_refs / evidence_hint_id. For TCP or no-packet cases, register as normal; do not guess IDs, and do not re-probe just to collect packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWhen a platform conversation has no task context, do not call report_finding directly; hand over to the matching existing task via add_task_hint, let the task agent register it, and check the result with list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore judging a goal complete, first finish reporting/handing over the evidence you already have. Do not end the task or cancel a Worker just because a vulnerability has been registered as text while the evidence handover is not yet finished; a no-packet case does not require waiting or forcing a capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Automatic traffic linking before the report (enabled)**: you are responsible for checking and binding traffic for the vulnerability triggered this time, then writing the report. First get the exact finding_id and finding_node_id from the JSON returned by report_finding or from get_task_node_detail / list_task_findings. Read the vulnerability detail, the execution record of the matching intent and the existing evidence list, preferring the real IDs handed over by the reporter. If this verification was HTTP and the traffic tools are available, use traffic_search to filter candidates, then traffic_get to check each request/response really supports the vulnerability; domain and time are only for filtering and do not prove ownership. Link the confirmed evidence in reproduction order with bind_finding_traffic(finding_id, traffic_refs), choosing baseline / proof / verification / supporting and stating its purpose. Work only on this vulnerability; do not recreate vulnerabilities or re-probe the target. After a successful binding, call get_finding_traffic again to get the latest version, read the bodies you need, then pass the version you actually read as evidence_version to update_finding_report (whose finding_id parameter still uses finding_node_id). Existing bindings need not be re-added. For TCP, nothing captured, tools unavailable or no exact match, skip automatic binding, write the report as normal from the text/command evidence and explain why, and do not guess to make up traffic. On a binding failure do not claim success; keep the existing evidence and explain in the report why nothing was bound."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional: verified traffic references matching the specific vulnerability in this hint, order preserved; after handover report_finding can pass evidence_hint_id to carry these references.", "items": obj(map[string]any{"traffic_id": str("real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("what conclusion this traffic supports")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be a hint node of this task (an inherited hint cannot be used directly for binding)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
