package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract for the notification_channels.filter JSONB column: a channel instance's filter conditions.
// Every field is optional and absent means "no filtering", which is exactly the fallback semantics for a malformed configuration; see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity threshold (low/medium/high/critical); empty = no threshold.
	MinSeverity string `json:"min_severity"`
	// An empty TaskIDs / AssetIDs array means unrestricted; non-empty requires the event to overlap with it.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// An empty VulnClassInclude accepts everything; non-empty requires vulnclass to match any one of the keywords.
	// VulnClassExclude excludes on a match with any keyword (exclusion takes precedence over inclusion).
	// Matching is a case-insensitive substring, which is safer than regular expressions: a user's broken regex cannot make a channel fail silently.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange decides whether this channel receives vulnerability status change events (only meaningful in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses a channel's filter configuration.
//
// **It never returns an error.** This is a deliberate design choice: a malformed filter configuration always degrades to the zero-value
// Filter (= no filtering = everything matches), because for a vulnerability notification system **sending one too many is far better than
// silently missing a critical one**. Turning a parse failure into "do not send" would give the user a channel that looks configured
// but actually sends nothing, which is the worst failure mode of all.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// On a parse failure f stays at its zero value, i.e. no filtering.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid severity threshold (an empty string means no threshold).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the **restricted-value** fields in a filter configuration, called when a channel is saved.
//
// Why this must be caught on write: Match judges an unknown threshold as `rank >= 0`, which is always true;
// in other words a typo in min_severity ("hgih") makes the filter **fail silently** and become
// "send everything". That fits this package's "better to over-send than miss one" trade-off (nothing is missed),
// but the result is that users think they are sending by severity while actually pouring every vulnerability into the group,
// with no sign at all that they misconfigured it. This kind of "silent degradation" should be stopped at the entrance.
//
// Note that Validate is only used on the **write** path. The read path still uses ParseFilter's lenient semantics,
// so bad values already present in historical data cannot make a channel unreadable.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("invalid minimum severity %q; choose low / medium / high / critical, or leave blank for no limit", f.MinSeverity)
	}
	return nil
}

// Match decides whether an event should be delivered to a channel with this filter.
//
// **It never returns an error**, for the same reason as ParseFilter: any internal anomaly is treated as a "match".
// Order of checks: event type → severity threshold → task/asset scope → vulnerability type keywords.
func Match(f Filter, s Snapshot) bool {
	// Only channels that explicitly opt in receive status change events. Off by default, because most users
	// expect "notifications" to mean "a new vulnerability was found", not a running log of every status transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclusion first: matching any exclusion keyword rules it out, even if it also matches the inclusion list.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// A linear scan is fine for small sets; both sides are on the order of "a few dozen picked by hand",
	// so building a map costs more than it saves.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any keyword in keywords (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
