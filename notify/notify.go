// Package notify implements the IM / email notification channel adapter layer for vulnerability findings.
//
// Layering: this is a **leaf package** that depends only on the standard library. It knows nothing about the database or the server. Channel configs
// are passed in as map[string]any (matching the notification_channels.config JSONB column), and the content to send
// is passed in as a Message. The benefit of this split is that the genuinely error-prone parts (signature calculation, UTF-8 truncation, filter matching)
// can be unit-tested without PostgreSQL, and the host only needs to orchestrate on the server side.
//
// Concurrency contract: Channel implementations must be **stateless**. The same Channel instance is reused concurrently by several channel configs
// (even several bot instances of the same channel), and all credentials are passed in through the cfg parameter;
// things like webhook URLs must never be cached in the implementation's own fields.
package notify

// Channel type identifiers. The values are also the valid set for notification_channels.kind, checked against an allowlist on the server
// side (as with findings.status, there is no DB CHECK, which makes adding channels later easier).
const (
	KindDingTalk = "dingtalk" // DingTalk custom bot
	KindFeishu   = "feishu"   // Feishu (including Lark) custom bot
	KindWeCom    = "wecom"    // WeCom group bot
	KindWebhook  = "webhook"  // Generic webhook: custom method/headers/JSON template
	KindTelegram = "telegram" // Telegram Bot API
	KindEmail    = "email"    // SMTP email
)

// Event types, matching notification_events.kind.
const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

// InitKind is the fallback value for an empty kind in config.
const InitKind = KindDingTalk

// severityRank maps a vulnerability severity to a comparable ordinal. Unknown severities return 0, so any
// min_severity setting keeps them out: when in doubt, do not notify, to avoid flooding with false alarms.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns the severity's ordinal; unknown severities return 0.
func SeverityRank(severity string) int { return severityRank[severity] }

// SeverityLabel returns the severity name with an emoji, used for message titles and card colours.
// Unknown severities are echoed back unchanged rather than invented.
func SeverityLabel(severity string) string {
	switch severity {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🔵 Low"
	default:
		return severity
	}
}

// StatusLabel turns a triage status into a display label, used in status change messages.
func StatusLabel(status string) string {
	switch status {
	case "pending":
		return "Open"
	case "in_progress":
		return "In progress"
	case "confirmed":
		return "Confirmed"
	case "resolved":
		return "Handled"
	case "fixed":
		return "Fixed"
	case "false_positive":
		return "False positive"
	case "ignored":
		return "Ignored"
	case "duplicate":
		return "Duplicate"
	case "risk_accepted":
		return "Risk accepted"
	default:
		return status
	}
}

// AtLeast reports whether severity meets the min threshold. An empty min means no threshold, so everything passes.
// Note that an unknown severity has ordinal 0 and is rejected by any non-empty min (see the severityRank comment).
func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
