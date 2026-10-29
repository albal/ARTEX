package agent

import (
	"strings"

	"github.com/Autumn-27/artex/db"
)

// constraintBlock renders this task's operation constraints (task_constraints) as a
// high-priority block appended to the planner/worker system prompt. allow/deny are
// grouped; empty string when there are no constraints (or ts is nil). The framing
// deliberately puts these ABOVE the exploration/expansion heuristics so a declared
// boundary wins the tug-of-war against "chase another entry surface".
func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	var allow, deny []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else {
			deny = append(deny, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Operational constraints (highest priority, overriding every exploration/surface-expansion heuristic below; before generating each intent and before performing each action you must first self-check whether it is violated, and if so you must not proceed)]:")
	if len(allow) > 0 {
		b.WriteString("\nPermitted operations:\n")
		b.WriteString(strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("\nForbidden operations:\n")
		b.WriteString(strings.Join(deny, "\n"))
	}
	b.WriteString("\n(Finding a new goal/new port/new host outside the constraints does not mean authorisation has been granted: unless it falls within the permitted scope above, record it as an out-of-scope fact and skip it; do not derive intents or perform actions for it.)")
	return b.String()
}
