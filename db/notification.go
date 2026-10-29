package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/notify"
)

// This file is the channel configuration and event layer for IM notifications. Delivery task claiming and status transitions are in
// db/notification_delivery.go.
//
// Two invariants, which must be kept when changing this file:
//
//  1. the vulnerability-writing transaction (RecordFindingTx) only calls InsertNotificationEventTx to do one blind insert,
//     reading no notification-related table and doing no filter matching. Any read introduced here could, because of
//     a user's misconfigured filter, pollute or even abort the vulnerability write transaction.
//  2. filter matching never errors: a malformed configuration is always treated as a "match" (see notify.Match). Better to over-notify,
//     not to miss one.

// ErrNotificationChannelNotFound: the channel does not exist.
var ErrNotificationChannelNotFound = errors.New("notification channel does not exist")

// delivery status.
const (
	NotifyStatePending = "pending" // awaiting send
	NotifyStateSending = "sending" // claimed by a dispatcher, lease not yet expired
	NotifyStateSent    = "sent"    // delivered
	NotifyStateFailed  = "failed"  // retries exhausted or a permanent failure, can be resent manually
	NotifyStateSkipped = "skipped" // the channel is disabled, no longer sent
)

// notification mode.
const (
	NotifyModeRealtime = "realtime"
	NotifyModeDigest   = "digest"
)

// ValidNotifyMode allowlist-validates the notification mode (as with findings.status: no DB CHECK,
// for easier extension later).
func ValidNotifyMode(m string) bool {
	return m == NotifyModeRealtime || m == NotifyModeDigest
}

// NotificationChannel is one channel instance configuration. Config and Filter keep their raw JSON,
// parsing left to the notify package — the db layer does not understand their fields.
type NotificationChannel struct {
	ID     int64           `json:"id"`
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Mode   string          `json:"mode"`
	Config json.RawMessage `json:"config"`
	Filter json.RawMessage `json:"filter"`
	// Enabled is a pointer to distinguish "this field was not sent" from "explicitly sent false" —
	// the frontend toggle control only submits the fields that were changed.
	Enabled    *bool     `json:"enabled,omitempty"`
	RatePerMin int       `json:"rate_per_min"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IsEnabled returns whether the channel is enabled; when Enabled is nil (not loaded) it is treated as enabled.
func (c *NotificationChannel) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// NotificationEvent is one event fact.
type NotificationEvent struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	FindingID int64           `json:"finding_id"`
	Snapshot  json.RawMessage `json:"snapshot"`
	CreatedAt time.Time       `json:"created_at"`
}

const notificationChannelCols = `id, name, kind, enabled, config, mode, filter, rate_per_min, created_at, updated_at`

func scanNotificationChannel(sc interface{ Scan(...any) error }) (*NotificationChannel, error) {
	var c NotificationChannel
	var enabled bool
	if err := sc.Scan(&c.ID, &c.Name, &c.Kind, &enabled, &c.Config, &c.Mode, &c.Filter, &c.RatePerMin, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.Enabled = &enabled
	return &c, nil
}

// ListNotificationChannels returns every channel instance, enabled ones first, then by id within the same group.
// The sort is in SQL so the UI and the dispatcher see the same stable order.
func (d *DB) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels
ORDER BY enabled DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationChannel{}
	for rows.Next() {
		c, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NotificationChannelByID fetches a single channel.
func (d *DB) NotificationChannelByID(ctx context.Context, id int64) (*NotificationChannel, error) {
	row := d.QueryRowContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels WHERE id=$1`, id)
	c, err := scanNotificationChannel(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotificationChannelNotFound
	}
	return c, err
}

// SaveNotificationChannel creates or updates a channel.
//
// On update it only overwrites the fields the caller explicitly gave (non-nil / non-empty), so the frontend can submit a partially
// modified drawer form without sending back the config fields it did not display — sending them back would instead cause
// the "mask value overwrites the real key" accident.
func (d *DB) SaveNotificationChannel(ctx context.Context, c *NotificationChannel) (int64, error) {
	if c.Mode == "" {
		c.Mode = NotifyModeRealtime
	}
	// It deliberately does **not** process 0 in any way: 0 is a valid configuration, meaning "no rate limit".
	//
	// This was once written as `if c.RatePerMin <= 0 { c.RatePerMin = default }`, intending "give a safe default when unspecified",
	// but that also swallowed "explicitly set to 0" — the docs, the UI hint and
	// takeTokens all interpret 0 as no rate limit, yet here alone it was quietly changed to 20 (DingTalk/WeCom/Telegram)
	// or 100 (Feishu), so the operator thought the limit was lifted while actually being held at 20/minute with no hint.
	//
	// only the caller knows the difference between "unspecified" and "explicitly 0" (the field absent in the request body vs explicitly 0),
	// so the default is filled by the server layer when the field is absent, see notifyCreateChannel.
	if c.RatePerMin < 0 {
		return 0, errors.New("the rate limit must not be negative")
	}
	if c.Config == nil {
		c.Config = json.RawMessage(`{}`)
	}
	if c.Filter == nil {
		c.Filter = json.RawMessage(`{}`)
	}
	enabled := c.IsEnabled()

	if c.ID == 0 {
		var id int64
		err := d.QueryRowContext(ctx, `INSERT INTO notification_channels(name,kind,enabled,config,mode,filter,rate_per_min)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			c.Name, c.Kind, enabled, string(c.Config), c.Mode, string(c.Filter), c.RatePerMin).Scan(&id)
		return id, err
	}
	res, err := d.ExecContext(ctx, `UPDATE notification_channels
SET name=$2, kind=$3, enabled=$4, config=$5, mode=$6, filter=$7, rate_per_min=$8
WHERE id=$1`,
		c.ID, c.Name, c.Kind, enabled, string(c.Config), c.Mode, string(c.Filter), c.RatePerMin)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotificationChannelNotFound
	}
	return c.ID, nil
}

// SetNotificationChannelEnabled toggles enable/disable.
//
// When disabling a channel, mark its not-yet-sent deliveries as skipped too: otherwise after re-enabling
// it would suddenly receive a batch of old vulnerabilities "backlogged while disabled", now stale and easily mistaken for new.
func (d *DB) SetNotificationChannelEnabled(ctx context.Context, id int64, enabled bool) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE notification_channels SET enabled=$2 WHERE id=$1`, id, enabled)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotificationChannelNotFound
		}
		if !enabled {
			if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET state=$2, last_error=$3
WHERE channel_id=$1 AND state IN ($4,$5)`,
				id, NotifyStateSkipped, "channel disabled", NotifyStatePending, NotifyStateSending); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteNotificationChannel deletes a channel. Its delivery history is cascade-deleted by the foreign key
// (with the channel config gone, the history cannot be interpreted).
func (d *DB) DeleteNotificationChannel(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotificationChannelNotFound
	}
	return nil
}

// RecordNotificationEventTx writes one notification event in the caller's transaction on a **best-effort** basis.
//
// This is the only notification-related change on the vulnerability write path: one INSERT, reading no table, not knowing channels,
// running no filter. Committing the transaction guarantees "the vulnerability is stored" and "the notification task exists" are atomically consistent,
// with no window where the commit succeeds but nothing was enqueued and the message is lost forever.
//
// Two key designs, neither written casually:
//
//  1. **why SAVEPOINT**: in PostgreSQL, an error in any statement within a transaction puts the whole transaction into
//     the aborted state, after which every statement (including COMMIT) fails. So "ignore this INSERT's
//     error and let the caller carry on committing" is impossible in PG — unless a savepoint isolates the error to
//     this one statement. Without a savepoint, "roll the whole thing back" is the only option left.
//
//  2. **why rolling the whole thing back is wrong**: notifications are a convenience; the vulnerability record is the product itself. A problem in a notification
//     table (an old database not migrated, a transient disk fault) should not stop a critical vulnerability being stored. So the error is isolated here,
//     logged, and false returned, letting the vulnerability write commit as normal — at the cost of dropping this one notification.
//     Returning a bool rather than an error is deliberate: the caller should not treat it as an error affecting write success.
func RecordNotificationEventTx(ctx context.Context, tx *sql.Tx, kind string, findingID int64, snap notify.Snapshot) bool {
	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[notify] failed to serialise the notification event finding=%d: %v", findingID, err)
		return false
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT notify_event`); err != nil {
		log.Printf("[notify] failed to create the savepoint finding=%d: %v", findingID, err)
		return false
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,$2,$3)`,
		kind, findingID, string(raw)); err != nil {
		log.Printf("[notify] failed to write the notification event finding=%d (the vulnerability record is unaffected): %v", findingID, err)
		// roll back to the savepoint, rescuing the transaction from the aborted state.
		if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT notify_event`); rbErr != nil {
			log.Printf("[notify] failed to roll back to the savepoint finding=%d: %v", findingID, rbErr)
		}
		return false
	}
	// release the savepoint, to avoid accumulating useless savepoints in a long transaction.
	_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT notify_event`)
	return true
}

// AddNotificationEvent is the standalone-transaction version of InsertNotificationEventTx, for call sites not
// inside an existing transaction (such as a channel's "send test message", which has no real finding).
func (d *DB) AddNotificationEvent(ctx context.Context, kind string, findingID int64, snap notify.Snapshot) (int64, error) {
	raw, err := json.Marshal(snap)
	if err != nil {
		return 0, fmt.Errorf("failed to serialise the notification event snapshot: %w", err)
	}
	var id int64
	err = d.QueryRowContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,$2,$3) RETURNING id`,
		kind, findingID, string(raw)).Scan(&id)
	return id, err
}

// FanOutPendingEvents expands vulnerability events not yet dispatched into delivery tasks for the currently enabled channels,
// returning the number of events processed and deliveries created this round.
//
// The whole round runs in one transaction: events are claimed with FOR UPDATE SKIP LOCKED, so several processes running at once
// each claim different rows (the project's archive queue claiming uses the same technique, see
// completeNextArchiveJob in db/task_archives.go).
//
// Filter matching is deliberately on the Go side rather than in SQL: a channel's filter is a set of optional fields in JSONB,
// and expressing the six-combination match in SQL would make the query hard to maintain, whereas the number of channels is "a few configured by hand",
// so loading them all and comparing in memory is both faster and easier to test.
//
// An event matching no channel is also marked fanned_out — otherwise it would stay in the to-dispatch set forever,
// rescanned every tick.
func (d *DB) FanOutPendingEvents(ctx context.Context, limit int) (eventCount, deliveryCount int, err error) {
	if limit <= 0 {
		limit = 200
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a successful commit

	channels, err := listEnabledNotificationChannelsTx(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, kind, finding_id, snapshot FROM notification_events
WHERE NOT fanned_out ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return 0, 0, err
	}
	var (
		events      []NotificationEvent
		parsedSnaps []notify.Snapshot
	)
	for rows.Next() {
		var ev NotificationEvent
		if err := rows.Scan(&ev.ID, &ev.Kind, &ev.FindingID, &ev.Snapshot); err != nil {
			rows.Close()
			return 0, 0, err
		}
		var snap notify.Snapshot
		// the snapshot is written by us and should always parse; a parse failure does not block the delivery flow,
		// but this event, with all fields empty, is skipped by every channel that has a filter — better to send one fewer
		// than to let one bad row jam the whole queue.
		_ = json.Unmarshal(ev.Snapshot, &snap)
		// kind takes the in-row value as authoritative: the copy in the snapshot is for rendering and may have been written by an older version.
		snap.Kind = ev.Kind
		events = append(events, ev)
		parsedSnaps = append(parsedSnaps, snap)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(events) == 0 {
		return 0, 0, tx.Commit()
	}

	type pending struct {
		eventID   int64
		channelID int64
	}
	var toInsert []pending
	for i, snap := range parsedSnaps {
		for _, ch := range channels {
			if !notify.Match(notify.ParseFilter(ch.Filter), snap) {
				continue
			}
			toInsert = append(toInsert, pending{eventID: events[i].ID, channelID: ch.ID})
		}
	}
	if len(toInsert) > 0 {
		var (
			vals []string
			args []any
		)
		for _, p := range toInsert {
			vals = append(vals, fmt.Sprintf("($%d,$%d)", len(args)+1, len(args)+2))
			args = append(args, p.eventID, p.channelID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id) VALUES `+strings.Join(vals, ","), args...); err != nil {
			return 0, 0, err
		}
	}

	// mark this round's events as dispatched. Events matching no channel are marked too (see the function comment).
	ids := make([]string, 0, len(events))
	markArgs := make([]any, 0, len(events))
	for _, ev := range events {
		markArgs = append(markArgs, ev.ID)
		ids = append(ids, fmt.Sprintf("$%d", len(markArgs)))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notification_events SET fanned_out=true WHERE id IN (`+strings.Join(ids, ",")+`)`, markArgs...); err != nil {
		return 0, 0, err
	}
	return len(events), len(toInsert), tx.Commit()
}

// listEnabledNotificationChannelsTx fetches the enabled channels within the transaction. There are very few,
// so there is no paging and no cache — a cache would introduce the extra timing problem of "when does a config change take effect".
func listEnabledNotificationChannelsTx(ctx context.Context, tx *sql.Tx) ([]*NotificationChannel, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name, kind, config, mode, filter, rate_per_min
FROM notification_channels WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationChannel{}
	for rows.Next() {
		var c NotificationChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.Mode, &c.Filter, &c.RatePerMin); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// NotificationAssetNames resolves asset ids into short display names for notification messages.
//
// The return order matches the input, and the length may be smaller (non-existent ids are skipped). Keeping the input order is
// so one vulnerability's message has a stable asset order across several deliveries — otherwise the asset order in a message received after a retry
// would change and be misread as "the assets changed".
func (d *DB) NotificationAssetNames(ctx context.Context, ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ph, args := placeholders(1, ids)
	rows, err := d.QueryContext(ctx, `SELECT id, type, domain, ip, url, app_name, bundle_id FROM assets WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	labels := map[int64]string{}
	for rows.Next() {
		var (
			id                int64
			typ               string
			domain, ip, url   sql.NullString
			appName, bundleID sql.NullString
		)
		if err := rows.Scan(&id, &typ, &domain, &ip, &url, &appName, &bundleID); err != nil {
			return nil, err
		}
		labels[id] = assetDisplayName(typ, domain.String, ip.String, url.String, appName.String, bundleID.String)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if label, ok := labels[id]; ok && label != "" {
			out = append(out, label)
		}
	}
	return out, nil
}

// assetDisplayName picks the most identifiable label by asset type.
// It falls back to an empty string, leaving the caller to decide how to present an "asset whose name cannot be obtained" — this function invents no placeholder,
// otherwise noise like "asset #42" would creep into notification messages and readers would think it a real domain.
func assetDisplayName(typ, domain, ip, url, appName, bundleID string) string {
	pick := func(vals ...string) string {
		for _, v := range vals {
			if strings.TrimSpace(v) != "" {
				return v
			}
		}
		return ""
	}
	switch typ {
	case "root_domain", "subdomain":
		return domain
	case "ip":
		return ip
	case "app":
		return pick(appName, bundleID)
	case "service", "endpoint":
		return pick(url, domain, ip)
	default:
		return pick(domain, ip, url, appName)
	}
}

// SetFindingStatusWithNotify updates a vulnerability's triage status and, in the same transaction, registers a status-change
// notification event.
//
// Returns from = the status before the change; found = whether the vulnerability exists; notified = whether the event was registered successfully.
//
// Three deliberate behaviours:
//   - no event is registered when the status does not actually change. A frontend drawer resubmitting the same value, or an automation script
//     replaying idempotently, should not produce notification noise.
//   - when the vulnerability does not exist it returns found=false and does no write, for the caller to translate into a 404.
//   - a failed event registration does not affect the status update (see the savepoint note in RecordNotificationEventTx),
//     so when notified=false the status has already changed successfully, and the caller should not error because of it.
func (d *DB) SetFindingStatusWithNotify(ctx context.Context, id int64, status string) (from string, found bool, notified bool, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var txErr error
		from, found, _, notified, txErr = SetFindingStatusTx(ctx, tx, id, status)
		return txErr
	})
	return from, found, notified, err
}

// SetFindingStatusTx updates a vulnerability's status and registers a status-change notification event within the **caller's transaction**.
//
// It is factored into a transaction-level function so every status-changing path shares the same semantics — previously only
// patchFinding used the version with notification, while **when a retest concluded "fixed"** (that `UPDATE findings SET status=...`
// in finding_retests) wrote to the database directly, so a channel configured with
// `on_status_change` received no notification at all for this kind of status transition: the status changed quietly in the interface, and
// operators only found out by opening the platform.
//
// Returns from = the status before the change, found = whether the vulnerability exists, changed = whether the status actually changed,
// notified = whether the event was registered successfully (a failed registration does not affect the status update, see RecordNotificationEventTx).
func SetFindingStatusTx(ctx context.Context, tx *sql.Tx, id int64, status string) (from string, found bool, changed bool, notified bool, err error) {
	var (
		vulnclass, name, severity, summary string
		taskID                             sql.NullInt64
		assetIDs                           []byte
	)
	scanErr := tx.QueryRowContext(ctx, `SELECT vulnclass, name, severity, summary, task_id, asset_ids, status
FROM findings WHERE id=$1 FOR UPDATE`, id).
		Scan(&vulnclass, &name, &severity, &summary, &taskID, &assetIDs, &from)
	if scanErr == sql.ErrNoRows {
		return "", false, false, false, nil
	}
	if scanErr != nil {
		return "", false, false, false, scanErr
	}
	found = true
	if from == status {
		// do not register an event when the status did not actually change: a resubmission of the same value or an idempotent replay should not
		// produce notification noise.
		return from, true, false, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status=$2 WHERE id=$1`, id, status); err != nil {
		return from, true, false, false, err
	}
	var assets []int64
	_ = json.Unmarshal(assetIDs, &assets)
	notified = RecordNotificationEventTx(ctx, tx, notify.EventFindingStatusChanged, id, notify.Snapshot{
		Kind:       notify.EventFindingStatusChanged,
		FindingID:  id,
		TaskID:     taskID.Int64,
		VulnClass:  vulnclass,
		Name:       name,
		Severity:   severity,
		Summary:    summary,
		AssetIDs:   assets,
		FromStatus: from,
		ToStatus:   status,
	})
	return from, true, true, notified, nil
}

// NotificationStats is the overview count at the top of the notifications page.
type NotificationStats struct {
	Channels     int   `json:"channels"`
	ChannelsOn   int   `json:"channels_on"`
	Pending      int   `json:"pending"`
	Failed       int   `json:"failed"`
	SentToday    int   `json:"sent_today"`
	BacklogAgeMS int64 `json:"backlog_age_ms"` // milliseconds since the oldest not-yet-sent delivery
}

// NotificationStatsSnapshot summarises the notification system's health.
// BacklogAgeMS is the most direct indicator of "are notifications stuck" — far more useful than the pending count,
// because the difference between a backlog of 3 and a backlog of 3 can be anything from 3 seconds to 3 hours.
func (d *DB) NotificationStatsSnapshot(ctx context.Context) (*NotificationStats, error) {
	var s NotificationStats
	if err := d.QueryRowContext(ctx, `SELECT
    (SELECT count(*) FROM notification_channels),
    (SELECT count(*) FROM notification_channels WHERE enabled),
    (SELECT count(*) FROM notification_deliveries WHERE state IN ($1,$2)),
    (SELECT count(*) FROM notification_deliveries WHERE state=$3),
    (SELECT count(*) FROM notification_deliveries WHERE state=$4 AND sent_at >= date_trunc('day', now())),
    COALESCE((SELECT EXTRACT(EPOCH FROM (now() - min(created_at))) * 1000 FROM notification_deliveries WHERE state=$1), 0)::bigint`,
		NotifyStatePending, NotifyStateSending, NotifyStateFailed, NotifyStateSent).
		Scan(&s.Channels, &s.ChannelsOn, &s.Pending, &s.Failed, &s.SentToday, &s.BacklogAgeMS); err != nil {
		return nil, err
	}
	return &s, nil
}
