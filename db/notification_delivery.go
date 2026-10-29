package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// This file is delivery task claiming and status transitions.
//
// Claiming uses a "lease" rather than a long transaction: the row is set to sending and next_attempt_at pushed into the future as
// the lease expiry, then the transaction commits before the network delivery is done. This way no database lock is held during delivery —
// a network request can take several seconds (the client times out at 15), and holding a row lock would drag down other writes on the same database.
//
// The cost is that if the process crashes mid-delivery the row is left in sending. This is **self-healing**: once the lease expires
// next_attempt_at is in the past, and the next claim round picks the same row up again (see state IN ('pending','sending')
// in the claim condition). The retry count is already +1 at claim time, so a crash does not cause
// infinite retries — after MaxNotifyAttempts chances it falls into failed for manual handling.

// MaxNotifyAttempts is the maximum number of attempts for one delivery (including the first).
// Defined here rather than in the delivery engine: it is the state machine's own policy, and the engine is only the executor.
const MaxNotifyAttempts = 3

// MaxDigestBatchSize is the most deliveries one digest batch merges at once.
//
// The reason it exists is resource: if a digest window finds tens of thousands of vulnerabilities (entirely possible — one full scan
// can do it), with no upper bound a claim would read all the rows into memory, render one extremely long message,
// and then have most of it cut off by the channel's length limit — wasting memory and **silently losing** the cut vulnerabilities.
// With an upper bound, the excess stays in the database as the next batch, sent out naturally next window, and is not lost.
//
// The basis for 500: it is the magnitude that, rendered into a message, still has "readable content" within WeCom's 4096-byte limit;
// any larger just makes the truncation happen further along.
const MaxDigestBatchSize = 500

// NotificationDelivery is one delivery task, carrying the channel config and event snapshot needed for rendering.
type NotificationDelivery struct {
	ID            int64           `json:"id"`
	EventID       int64           `json:"event_id"`
	ChannelID     int64           `json:"channel_id"`
	State         string          `json:"state"`
	Attempts      int             `json:"attempts"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
	LastError     string          `json:"last_error"`
	BatchID       *int64          `json:"batch_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	SentAt        *time.Time      `json:"sent_at,omitempty"`
	Snapshot      json.RawMessage `json:"snapshot,omitempty"`
	// the joint-loaded rendering context, not in the JSON (the server layer assembles the DTO).
	Channel *NotificationChannel `json:"-"`
	// FindingID/EventKind are carried over from the event, so the history list can jump straight to the vulnerability detail.
	FindingID int64  `json:"finding_id,string"`
	EventKind string `json:"event_kind"`
	// ChannelName/ChannelKind are redundant fields for the list display, saving the frontend a second query.
	ChannelName string `json:"channel_name"`
	ChannelKind string `json:"channel_kind"`
}

const notificationDeliveryCols = `d.id, d.event_id, d.channel_id, d.state, d.attempts, d.next_attempt_at,
       d.last_error, d.batch_id, d.created_at, d.sent_at`

// joinedDeliveryQuery is the unified read shape for a delivery row: delivery + event snapshot + channel config.
// All three are indispensable for rendering a message; querying them separately would mean three round-trips.
const joinedDeliveryQuery = `SELECT ` + notificationDeliveryCols + `,
       e.snapshot, e.kind, e.finding_id,
       c.id, c.name, c.kind, c.enabled, c.config, c.mode, c.filter, c.rate_per_min
FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id
JOIN notification_channels c ON c.id = d.channel_id`

func scanNotificationDelivery(sc interface{ Scan(...any) error }) (*NotificationDelivery, error) {
	var (
		dl        NotificationDelivery
		lastErr   sql.NullString
		batchID   sql.NullInt64
		sentAt    sql.NullTime
		snapshot  []byte
		eventKind string
		channel   NotificationChannel
		chEnabled bool
	)
	if err := sc.Scan(&dl.ID, &dl.EventID, &dl.ChannelID, &dl.State, &dl.Attempts, &dl.NextAttemptAt,
		&lastErr, &batchID, &dl.CreatedAt, &sentAt,
		&snapshot, &eventKind, &dl.FindingID,
		&channel.ID, &channel.Name, &channel.Kind, &chEnabled, &channel.Config, &channel.Mode, &channel.Filter, &channel.RatePerMin); err != nil {
		return nil, err
	}
	dl.LastError = lastErr.String
	if batchID.Valid {
		dl.BatchID = &batchID.Int64
	}
	if sentAt.Valid {
		dl.SentAt = &sentAt.Time
	}
	dl.Snapshot = json.RawMessage(snapshot)
	dl.EventKind = eventKind
	dl.ChannelName = channel.Name
	dl.ChannelKind = channel.Kind
	channel.Enabled = &chEnabled
	dl.Channel = &channel
	return &dl, nil
}

// claimQuery describes one claim: first select the candidates with sel and lock them, then set them to sending and
// extend the lease. The lease position in sel is placed by the caller with $n and passed in by them.
type claimQuery struct {
	sql  string
	args []any
}

// ClaimRealtimeDeliveries claims a batch of a channel's due realtime deliveries, at most limit.
//
// Deliberately claimed per **single channel** rather than "claim a global batch and pick ones to send": the rate limiter is maintained per channel in the delivery engine,
// and only by first knowing how many this channel can still send this round and then claiming that many rows does rate limiting not consume
// retry attempts. If instead you claim first and drop later, a row held off by rate limiting has already had its attempts counted once,
// and the 3-attempt budget would be burned by pure waiting, finally landing in failed.
//
// The condition includes "sending whose lease has expired" — that is the landing point for crash self-healing. The lease must be significantly larger than a single
// delivery's worst-case duration (the channel HTTP client times out at 15s), otherwise the same row would be delivered by two dispatchers
// at once. It also blocks disabled channels: the disable operation has marked existing deliveries as skipped,
// and this is a second guard against leaks when disabling and claiming run concurrently.
func (d *DB) ClaimRealtimeDeliveries(ctx context.Context, channelID int64, limit int, lease time.Duration) ([]*NotificationDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	return d.claimDeliveries(ctx, lease, claimQuery{
		sql: `SELECT dd.id FROM notification_deliveries dd
JOIN notification_channels c ON c.id = dd.channel_id
WHERE dd.channel_id = $1 AND dd.state IN ($2,$3) AND dd.next_attempt_at <= now()
  AND c.enabled AND c.mode = $4
ORDER BY dd.next_attempt_at, dd.id
FOR UPDATE OF dd SKIP LOCKED
LIMIT $5`,
		args: []any{channelID, NotifyStatePending, NotifyStateSending, NotifyModeRealtime, limit},
	}, nil)
}

// DigestBatchDue reports whether the channel has accumulated a due batch: there are not-yet-sent deliveries, and **the oldest one's**
// age has reached the digest window.
//
// The basis is the oldest delivery's age rather than the wall clock: this way a just-created channel does not, by aligning to the hour,
// immediately emit a one-item "digest", and a long-backlogged batch does not wait another round for nothing.
//
// It is separate from ClaimDigestBatch because the semantics differ: this function only answers "should it send",
// while claiming takes the channel's **entire** not-yet-sent set (including ones not yet old enough) — otherwise one window
// would be split into several messages and the digest would lose its point.
func (d *DB) DigestBatchDue(ctx context.Context, channelID int64, minAge time.Duration) (bool, error) {
	var due bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM notification_deliveries d
  JOIN notification_channels c ON c.id = d.channel_id
  WHERE d.channel_id = $1 AND d.state IN ($2,$3) AND c.enabled
  GROUP BY d.channel_id
  HAVING min(d.created_at) <= now() - make_interval(secs => $4)
)`, channelID, NotifyStatePending, NotifyStateSending, int64(minAge.Seconds())).Scan(&due)
	return due, err
}

// ClaimDigestBatch claims the channel's currently due not-yet-sent deliveries as one digest batch,
// at most MaxDigestBatchSize per batch.
//
// All deliveries in a batch share a batch_id, using the smallest id in the set as the batch number (stable, readable,
// needing no extra sequence). On retry, COALESCE keeps the original batch number, so "these N were sent together"
// still holds after several retries.
//
// The first N are taken by id ascending rather than at random: the earliest-produced deliveries are sent first, so a backlog does not cause
// "new vulnerabilities sent first, old ones forever queued behind" starvation.
func (d *DB) ClaimDigestBatch(ctx context.Context, channelID int64, limit int, lease time.Duration) ([]*NotificationDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	// limit is the **memory upper bound**, and the caller passes MaxDigestBatchSize; it is clamped again here,
	// to guard against the caller passing a larger value.
	//
	// It deliberately does not accept a "rate-limit quota" as the batch size: the unit of rate limiting is the number of messages — one batch sends
	// one message and consumes one token, deducted by the server layer's takeTokens — a different dimension from "how many
	// vulnerabilities a batch holds". It was once, to make rate_per_min apply to the digest, given the per-round
	// request budget as the batch size, and a rate=20/min channel then held only 1 vulnerability per batch, and the
	// digest degraded into a realtime notification with a digest wrapper. To change rate limiting, change takeTokens' want,
	// not here.
	if limit > MaxDigestBatchSize {
		limit = MaxDigestBatchSize
	}
	out, err := d.claimDeliveries(ctx, lease, claimQuery{
		sql: `SELECT dd.id FROM notification_deliveries dd
JOIN notification_channels c ON c.id = dd.channel_id
WHERE dd.channel_id = $1 AND dd.state IN ($2,$3) AND dd.next_attempt_at <= now() AND c.enabled
ORDER BY dd.id
FOR UPDATE OF dd SKIP LOCKED
LIMIT $4`,
		args: []any{channelID, NotifyStatePending, NotifyStateSending, limit},
	}, func(tx *sql.Tx, ids []int64) error {
		batchID := ids[0]
		for _, id := range ids {
			if id < batchID {
				batchID = id
			}
		}
		ph, idArgs := placeholders(2, ids)
		_, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET batch_id = COALESCE(batch_id, $1)
WHERE id IN (`+ph+`)`, append([]any{batchID}, idArgs...)...)
		return err
	})
	return out, err
}

// claimDeliveries performs "select + set sending and extend the lease + read the full rows", all in one transaction.
// postClaim is an optional extra step (the digest batch uses it to write batch_id).
func (d *DB) claimDeliveries(ctx context.Context, lease time.Duration, cq claimQuery, postClaim func(*sql.Tx, []int64) error) ([]*NotificationDelivery, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a successful commit

	ids, err := selectForClaim(ctx, tx, cq.sql, cq.args...)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, tx.Commit()
	}
	// set sending and push next_attempt_at into the future: this future moment is the lease expiry,
	// so "lease not yet expired" and "retry time not yet reached" share the same condition expression, needing no new column.
	ph, idArgs := placeholders(3, ids)
	if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, attempts=attempts+1, next_attempt_at=now()+make_interval(secs => $2)
WHERE id IN (`+ph+`)`,
		append([]any{NotifyStateSending, lease.Seconds()}, idArgs...)...); err != nil {
		return nil, err
	}
	if postClaim != nil {
		if err := postClaim(tx, ids); err != nil {
			return nil, err
		}
	}
	out, err := loadDeliveriesTx(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func selectForClaim(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func loadDeliveriesTx(ctx context.Context, tx *sql.Tx, ids []int64) ([]*NotificationDelivery, error) {
	ph, args := placeholders(1, ids)
	rows, err := tx.QueryContext(ctx, joinedDeliveryQuery+` WHERE d.id IN (`+ph+`) ORDER BY d.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationDelivery{}
	for rows.Next() {
		dl, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dl)
	}
	return out, rows.Err()
}

// MarkDeliveriesSent marks a batch of deliveries as delivered.
func (d *DB) MarkDeliveriesSent(ctx context.Context, ids []int64) error {
	ph, args := placeholders(2, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, sent_at=now(), last_error='' WHERE id IN (`+ph+`)`, append([]any{NotifyStateSent}, args...)...)
	return err
}

// RescheduleDeliveries returns a batch of deliveries to pending and pushes the retry time back.
//
// Returning to pending rather than introducing a new intermediate state is so "how many chances are left" is expressed in one place only
// (MaxNotifyAttempts), avoiding the state machine's branches growing with the retry policy.
func (d *DB) RescheduleDeliveries(ctx context.Context, ids []int64, delay time.Duration, errMsg string) error {
	ph, args := placeholders(4, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, next_attempt_at=now()+make_interval(secs => $2), last_error=$3
WHERE id IN (`+ph+`)`,
		append([]any{NotifyStatePending, delay.Seconds(), truncateNotifyError(errMsg)}, args...)...)
	return err
}

// DeferDeliveries returns a batch of deliveries to pending, immediately re-claimable, and **undoes the one attempt counted at claim time**.
//
// Its only use: when a digest message is sent in segments by the channel's length limit, items not fitted into this one are left for the next batch.
// That is not a failure, so it should not consume the retry budget — attempts was optimistically +1 at claim time,
// and must be subtracted back here. Otherwise a backlog of 500, split into 25 segments of 20 each,
// would have its tail items judged failed by MaxNotifyAttempts at segment 3, though they never erred at all.
//
// GREATEST(...,0) guards the case of "someone manually resent and zeroed attempts, then reached here",
// so the count does not go negative.
func (d *DB) DeferDeliveries(ctx context.Context, ids []int64, reason string) error {
	ph, args := placeholders(3, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$1, attempts=GREATEST(attempts-1, 0), next_attempt_at=now(), last_error=$2
WHERE id IN (`+ph+`)`,
		append([]any{NotifyStatePending, truncateNotifyError(reason)}, args...)...)
	return err
}

// FailDeliveries marks a batch of deliveries as finally failed, awaiting a manual resend in the delivery history.
func (d *DB) FailDeliveries(ctx context.Context, ids []int64, errMsg string) error {
	// Placeholders start at $3: $1 is state, $2 is last_error.
	ph, args := placeholders(3, ids)
	if len(args) == 0 {
		return nil
	}
	_, err := d.ExecContext(ctx, `UPDATE notification_deliveries SET state=$1, last_error=$2 WHERE id IN (`+ph+`)`,
		append([]any{NotifyStateFailed, truncateNotifyError(errMsg)}, args...)...)
	return err
}

// RetryNotificationDelivery manually resends one delivery: reset to pending, zero the retry count,
// due immediately. Zeroing the count is deliberate — a manual "resend" means the reason for the earlier failures has been dealt with,
// so limiting it by the old count makes no sense.
func (d *DB) RetryNotificationDelivery(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `UPDATE notification_deliveries
SET state=$2, attempts=0, next_attempt_at=now(), last_error=''
WHERE id=$1 AND state IN ($3,$4)`, id, NotifyStatePending, NotifyStateFailed, NotifyStateSkipped)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("delivery %d does not exist or its current status does not allow resending", id)
	}
	return nil
}

// NotificationDeliveryFilter is the query condition for the delivery history.
type NotificationDeliveryFilter struct {
	ChannelID int64
	State     string
	EventKind string
}

func (f NotificationDeliveryFilter) where() (string, []any) {
	var conds []string
	var args []any
	if f.ChannelID > 0 {
		args = append(args, f.ChannelID)
		conds = append(conds, fmt.Sprintf("d.channel_id=$%d", len(args)))
	}
	if f.State != "" {
		args = append(args, f.State)
		conds = append(conds, fmt.Sprintf("d.state=$%d", len(args)))
	}
	if f.EventKind != "" {
		args = append(args, f.EventKind)
		conds = append(conds, fmt.Sprintf("e.kind=$%d", len(args)))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListNotificationDeliveries returns the delivery history paginated, newest first.
func (d *DB) ListNotificationDeliveries(ctx context.Context, f NotificationDeliveryFilter, page, pageSize int) ([]*NotificationDelivery, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	where, args := f.where()

	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := fmt.Sprintf("%s%s ORDER BY d.id DESC LIMIT $%d OFFSET $%d",
		joinedDeliveryQuery, where, len(args)+1, len(args)+2)
	rows, err := d.QueryContext(ctx, q, append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*NotificationDelivery{}
	for rows.Next() {
		dl, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, dl)
	}
	return out, total, rows.Err()
}

// truncateNotifyError truncates an error message to the length the column accepts. The response body a channel returns can be long
// (especially a generic webhook hitting a self-hosted service), and not truncating would bloat the history list's payload.
func truncateNotifyError(msg string) string {
	const max = 500
	if len(msg) <= max {
		return msg
	}
	// step back on a character boundary, to avoid leaving half a UTF-8 character that the frontend displays as garbage.
	cut := max
	for cut > 0 && !isUTF8Start(msg[cut]) {
		cut--
	}
	return msg[:cut] + "…"
}

func isUTF8Start(b byte) bool { return b&0xC0 != 0x80 }

// placeholders generates the $n placeholder string from start and the matching arguments, for use in IN (...).
// For example start=3, ids=[7,8] → "$3,$4", [7,8].
func placeholders(start int, ids []int64) (string, []any) {
	ph := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		ph = append(ph, fmt.Sprintf("$%d", start+i))
		args = append(args, id)
	}
	return strings.Join(ph, ","), args
}
