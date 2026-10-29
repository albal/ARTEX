package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// global settings keys (stored in the settings key/value table, no table needed).
const (
	// settingNotifyEnabled is the master notification switch. On by default: it is for stopping everything at once during maintenance,
	// not the feature's enable condition — the real enable condition is "whether a channel is configured".
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the external URL used to build links back to vulnerability details
	// (such as https://artex.example.com). If blank, messages carry no link-back button.
	// the project has no reusable external-address config, so this adds one.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes is the digest mode window (minutes).
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick is the delivery engine's poll interval. 3 seconds is the ceiling on this engine's responsiveness,
	// and the main source of delay between "the vulnerability is stored" and "the message arrives at the IM".
	notifyTick = 3 * time.Second
	// notifyLease is the lease duration when claiming a delivery. It must be significantly larger than a single delivery's worst-case duration
	// (the notify package's HTTP client times out at 15 seconds), otherwise the same row would be delivered by two
	// dispatchers at once.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick limits the number of events dispatched per round, to avoid expanding the whole historical backlog
	// into delivery tasks at once when a channel is first enabled.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is the default digest window.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick is the per-round delivery cap for a channel with no rate limit set.
	// it exists to stop "a channel set to no rate limit + one scan finding thousands of vulnerabilities" dragging
	// a single loop round into a long block.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick is the most a single channel delivers per round.
	//
	// this cap is derived backwards from the **lease duration**: at claim time a row is given a lease (notifyLease = 3 minutes),
	// and if serial delivery in one round takes long enough that the worst-case duration exceeds the lease, the last few are not yet sent when the lease
	// expires. Within a single process it does not matter (Run is one goroutine running serially, a tick does not re-enter), but with **two
	// processes on the same database** the peer re-claims the lease-expired rows and sends them again, double-incrementing
	// attempts and judging them failed while the original process is still delivering.
	//
	// the value: a 3-minute lease / a 30-second single timeout = 6 is **exactly using up the lease** with zero margin,
	// so it cannot be used; 5 leaves the worst-case 150 seconds with a 30-second margin. This relationship is pinned by
	// TestNotifyTickBudgetFitsWithinLease — changing any one of notifyLease,
	// notifySendTimeout or this value makes that assertion fail.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout is a single delivery's timeout. It also determines the previous constant's value,
	// the two multiplied must not exceed notifyLease, see TestNotifyTickBudgetFitsWithinLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff is the backoff sequence for failure retries, indexed by the number of attempts made.
// the 3 chances (including the first) correspond to db.MaxNotifyAttempts, and the two must be changed together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// Notifier is the vulnerability notification delivery engine.
//
// alongside the Scheduler, run as an independent goroutine (see server.New). It deliberately does not reuse
// the Scheduler's tick: notifications' responsiveness requirement (3 seconds) differs from the triggers' business cadence,
// and their failures do not affect each other — notifications being stuck should not affect agent triggers.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu protects buckets. There are few channels and low contention, so one mutex is enough,
	// not worth a finer-grained structure.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is a single channel's token bucket.
//
// a token bucket rather than a "count per minute then reset" sliding window, because the latter's boundary effect is bad:
// sending 20 at the end of a window and 20 the next instant is 40 in one second to the platform,
// which gets rate limited; a token bucket refills at a constant rate and naturally avoids such a burst.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx ends. Started once by server.New.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step runs one round: dispatch new events first, then deliver due tasks.
//
// a failure in any step only logs and does not break the loop — a notification system fault must never escalate to a process-level problem.
// each tick is independent, and the next round retries naturally.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] failed to dispatch events: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] failed to read channels: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// the token bucket's unit of measure is **the number of messages** (equivalent to the number of HTTP requests), not the number of vulnerabilities.
		// in realtime mode the two are the same (one vulnerability, one message); in digest mode a whole batch of vulnerabilities is merged into
		// one message, so only one token is consumed.
		//
		// both modes ask the token bucket first, then claim by quota — the order cannot be reversed, otherwise a delivery held off by rate limiting
		// has already consumed a retry attempt.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns a digest channel's token consumption and batch-size upper bound this round.
//
// the two return values are **two different dimensions**, which is exactly why it is its own function:
//
//   - tokens is the number of messages. A batch of vulnerabilities merges into one message and sends one HTTP request, so it is always 1.
//     rate_per_min therefore still applies to digest (at most this many digest messages per minute).
//   - claimLimit is the most vulnerabilities this batch holds. It is constrained only by the memory upper bound, unrelated to the request budget.
//
// it was once, to make rate_per_min apply to digest, given the per-round request budget
// (notifyMaxSendsPerChannelPerTick, derived backwards from the lease) directly as the batch size.
// the result was that a rate_per_min=20 channel refilled only 1 token in a 3-second tick, so each digest
// message held only 1 vulnerability — the digest degraded into a "realtime notification with a digest wrapper", and the reader received a string
// of "1 new vulnerability in the last 30 minutes", while db.MaxDigestBatchSize was never reachable.
//
// this symptom is hard to catch in an end-to-end test (the existing cases all manually pass a large enough limit to
// stepDigest, bypassing the quota calculation in step), so the decision is kept here and pinned by
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget directly.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims and delivers a channel's realtime tasks, one vulnerability per message.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim realtime deliveries channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("channel type %q is not registered", ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// a render failure is a local data problem; retrying will not make it better.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest aggregates a channel's not-yet-sent deliveries into one message when the batch is due.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] failed to judge the digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] failed to claim the digest batch channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("channel type %q is not registered", ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// deliveries whose snapshot was broken and could not go into the message are explicitly judged failed. Without this they would stay
	// outside included — neither in the message nor in the failure list — and on a successful send their status would be
	// missed by the later bulk marking, staying in sending forever until the lease expires and they are claimed repeatedly.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := "the event snapshot could not be parsed, so this vulnerability cannot be rendered into a message"
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] failed to mark bad-snapshot deliveries failed channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] skipped %d deliveries whose snapshot could not be parsed channel=%d", len(skipped), ch.ID)
	}
	// hand send only the ones that made it into the message: included[i] corresponds strictly to msg.Items[i],
	// and send relies on this correspondence to land "the channel reported it fitted the first K" onto the right delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and transitions the status by the result.
//
// the same batch of deliveries (possibly dozens in digest mode) shares one send result: either delivered, or the whole batch retries.
// no per-item retry — a digest message is one message, and resending part of it would corrupt the batch semantics.
//
// the one exception is **segmentation caused by the channel length limit**: the channel reports it only fitted the first K,
// so from the K+1th on they must wait for the next batch rather than being marked successful along with the rest. Otherwise the truncated
// vulnerabilities are neither in the message nor in the failure list and vanish completely.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// cap a single delivery, to stop one stuck channel holding up the rest of this round's channels.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// the channel-reported count cannot exceed the number of deliveries; if it does, the rendering layer miscalculated,
			// and treating it as all delivered and noting the problem is better than writing the records wrongly.
			log.Printf("[notify] the channel reported %d delivered, exceeding the %d deliveries channel=%s, treating as all delivered",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] failed to mark delivered channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// this message has hit the channel length limit: the rest go straight back into the queue, continued by the next tick.
			// use DeferDeliveries rather than RescheduleDeliveries — this is not a failure,
			// so it should not consume the retry budget (attempts was optimistically +1 at claim time, and that is subtracted back there).
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf("this message hit the channel length limit, only the first %d were delivered, the rest wait for the next batch", delivered)); err != nil {
				log.Printf("[notify] failed to queue the segmented continuation channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// the channel neither errored nor said how many it delivered. Treat it as failed (going through backoff),
		// to stop this delivery being claimed repeatedly yet never marked off.
		err = fmt.Errorf("the channel did not report a delivered count (delivered=%d)", delivered)
	}

	// the failure handling is decided **per item**, not by the batch's maximum attempt count.
	//
	// it was once `if maxAttempts(deliveries) >= MaxNotifyAttempts` judging the whole batch, but the attempt counts in the batch
	// differ: an old delivery already retried twice (attempts=2) would drag a brand-new delivery in the same batch
	// (attempts=1) into failed with it — the new vulnerability is lost forever without a single retry used,
	// exactly the opposite of the intent of "do not let old rows drag new ones down".
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] error marking failed state channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf("still failing after %d retries: %s", db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] error marking failed state channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// reschedule grouped by delay: with only 3 backoff tiers, the number of groups is naturally small, with no need to send a separate
	// UPDATE per item (that would make a batch of 500 do 500 round-trips).
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] failed to reschedule deliveries channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] delivery failed channel=%d kind=%s permanent=%d retries-exhausted=%d awaiting-retry=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns those in all not in keep (compared by pointer identity).
// used to find the "did not make it into the message" deliveries — they must be explicitly handled, not left in a grey zone.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt gets the channel implementation and parses its configuration.
// ok=false means the type is not registered, so the delivery should be judged failed directly rather than retried forever.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// on a config parse failure give an empty map: the channel's own Validate reports "which field is missing",
		// and that error guides the user to a fix better than a JSON parse error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders a single-vulnerability message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch renders a digest message. It parses the snapshots one by one — if one is bad only that one is skipped,
// without letting it take the whole digest down.
//
// the returned included corresponds **strictly one-to-one** with msg.Items (the ith delivery ↔ the ith item).
// this correspondence is a hard requirement: the caller marks the first K deliveries delivered by "the channel reported it fitted the first K".
// if a bad snapshot is skipped here but the skipped delivery is not removed from included,
// the indices shift — a bad item that should fail would be marked delivered, and a good item misjudged as not delivered.
// the bad ones are explicitly marked failed by the caller, see stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// a bad snapshot does not go into the message, nor into included — its handling is the caller's responsibility
			// (explicitly marked failed, rather than slipping by among the "delivered").
			log.Printf("[notify] skipped an unparseable snapshot in the digest batch delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf("all %d deliveries in the digest batch could not be parsed", len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor renders an event snapshot into an item to send, also resolving the asset names and the detail link-back.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// a failure to resolve asset names should not block the notification: not reading a name is far lighter than not receiving the notification,
		// the message just has one fewer asset line.
		log.Printf("[notify] failed to resolve asset names finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// the detail page route is in web/src/app/(main)/function/findings/detail/page.tsx,
		// which reads the vulnerability id from the query parameter id.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens takes **at most want** tokens from the channel's token bucket, returning the number actually taken.
//
// one token = one message (one HTTP request). In realtime mode the caller passes as many as it wants;
// in digest mode a whole batch of vulnerabilities sends one message, so it passes 1.
//
// the bucket capacity is the channel's per-minute limit, refilled at a constant rate. ratePerMin<=0 means no rate limit,
// returning a finite but large enough value, to stop a single loop round being dragged by an unbounded backlog.
//
// the want cap is necessary: without it the whole bucket would be drained, while the caller has its own per-round cap, so
// extra tokens taken are both unusable and vanish before the next refill — the accumulated burst capacity is forever unreachable,
// and even "this round has no deliveries at all" would still deduct one.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// refill by the real elapsed time, at a rate of ratePerMin/60 per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// add a tiny epsilon before truncating: the token count is a floating-point accumulation, and when refilled in two parts
	// 0.5 + 0.5 can come to 0.9999999999, which int() truncates to 0 —
	// a mathematically full bucket from which no token can be taken. 1e-9 is far smaller than one token and will not let a real shortfall through.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the master switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL returns the external address for link-backs, with the trailing slash removed.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval returns the digest window, falling back to the default when invalid or unconfigured.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot parses the snapshot of the event matching a delivery.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf("the event snapshot of delivery %d is empty", dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf("failed to parse the event snapshot of delivery %d: %w", dl.ID, err)
	}
	if snap.Kind == "" {
		// the event type takes the event row as authoritative; the copy in the snapshot may have been written by an older version.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
