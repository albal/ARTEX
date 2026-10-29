package notify

// Snapshot is the contract for the notification_events.snapshot JSONB column. The writer is the db layer's
// vulnerability persistence transaction; the readers are the server layer's delivery engine and filter matching. It is defined in this package because it is
// a "notification domain" payload: db only serialises it and does not understand what the fields mean.
//
// Why the vulnerability fields are stored redundantly rather than looked up at render time: vulnerabilities are later renamed, re-graded and re-triaged,
// but a notification should reflect the conclusion **at the time it happened**; looking it up again would give the dangerously misleading
// "changed to low after the fact". It also means fan-out and rendering need not JOIN the findings/tasks/assets tables.
type Snapshot struct {
	// Event types: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Only non-empty when kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is one vulnerability to be sent, for channel rendering.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets are the resolved asset display names (such as domains/IPs). Filled in by the server layer;
	// this package does not touch the database and cannot get the names.
	Assets []string
	// DetailURL links back to the vulnerability details; empty means public_base_url is not configured and it is omitted when rendering.
	DetailURL string
	// Status change events only; when both are non-empty it renders as "Open → Fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether this item is a status change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the item's display title: the human-assigned name first, falling back to the vulnerability type vulnclass,
// and a placeholder when both are empty; it never outputs an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(Unnamed vulnerability)"
}

// Message is the complete content of one channel send.
type Message struct {
	// Length 1 for a single notification; a whole batch for a digest.
	// An empty slice is invalid; the caller must ensure at least one item.
	Items []Item
	// Batch=true renders it as a digest message (different title, with the time window and count).
	Batch bool
	// WindowMinutes is the digest interval (minutes), only used when Batch=true for the wording "last N minutes".
	// It is deliberately passed in explicitly from config rather than computed with time.Since at render time: keeping rendering deterministic makes it testable.
	WindowMinutes int
	// HomeURL is the platform dashboard address (the global public_base_url); if empty no dashboard link is included.
	HomeURL string
}
