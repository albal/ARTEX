package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// This file covers the notification feature's end-to-end behaviour: vulnerability stored → event → dispatch → a real HTTP send.
//
// One security note: these cases do **not** call the global Notifier.step(), only stepRealtime/stepDigest on the channels they create.
// The reason is that step() iterates every enabled channel in the database — on a development database with a real DingTalk/WeCom bot configured, the global step would push
// the vulnerabilities produced during the test straight into those groups. Calling per channel strictly limits the blast radius to the test's own fake receivers.
// vulnerabilities produced into those groups for real. Calling per channel strictly limits the blast radius to the test's own fake receivers.
//
// Cleanup: at the end of a case, delete the events it produced (cascading the deliveries) and the channels, leaving no backlog for real channels.
//
// Assertion style: stepRealtime/stepDigest return nothing and log internally, so what is asserted here is the
// **observable external behaviour** (what the fake receiver got, what state the delivery rows reached), not the function's
// return value — this is closer to the real call path than stubbing the return value.

// notifyFixture is the shared setup for this file's cases.
type notifyFixture struct {
	s       *Server
	pg      *db.DB
	request func(method, path, body string) *httptest.ResponseRecorder
	n       *Notifier
	// a self-built task/exploration: cases record vulnerabilities here, isolated from other cases' data.
	taskID int64
	expID  int64
	// events produced after cleanupMark are deleted together on cleanup.
	cleanupMark int64
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	// all the fake receivers in this file run on 127.0.0.1, while delivery refuses loopback addresses by default
	// (to prevent SSRF against same-machine services and cloud metadata). The test explicitly turns this switch on;
	// the guard's "refuse by default" behaviour is covered by the notify package's ssrf_test.go.
	t.Setenv(notify.AllowLocalTargetsEnv, "1")
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg

	// build a task of our own: the task created by the shared setup trafficEvidenceServer has no exploration id to hand,
	// and recording a vulnerability must provide it.
	task, err := s.m.CreateTask("notification test", "notification behaviour verification", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Exec(`DELETE FROM tasks WHERE id=$1`, taskID) })

	var mark int64
	if err := pg.QueryRow(`SELECT COALESCE(max(id),0) FROM notification_events`).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	// make the setup self-contained: mark events that existed before the fixture was built as already dispatched in one go.
	//
	// why this is needed: FanOutPendingEvents is **global** and would expand every undispatched event in the database
	// onto all matching channels. The shared setup trafficEvidenceServer itself records a vulnerability
	// (exactly the initial finding it returns), and other cases may leave residue too. Without isolation,
	// these stray events would be dispatched onto this case's channel, making "there should be N deliveries" assertions
	// flip on and off — and the flip depends on test execution order, harder to diagnose than a plain failure.
	if _, err := pg.Exec(`UPDATE notification_events SET fanned_out = true WHERE id <= $1 AND NOT fanned_out`, mark); err != nil {
		t.Fatal(err)
	}

	f := &notifyFixture{s: s, pg: pg, request: request, n: newNotifier(s), taskID: taskID, expID: task.ExpID, cleanupMark: mark}
	t.Cleanup(func() {
		if _, err := pg.Exec(`DELETE FROM notification_events WHERE id > $1`, f.cleanupMark); err != nil {
			t.Logf("failed to clean up notification events: %v", err)
		}
	})
	// the master switch must be on (other cases may have turned it off).
	if err := pg.SetBool(settingNotifyEnabled, true); err != nil {
		t.Fatal(err)
	}
	return f
}

// record writes a vulnerability through the real evidence path, returning the finding id.
// this path registers a notification event in the **same transaction** — exactly this feature's hook.
func (f *notifyFixture) record(t *testing.T, vulnclass, severity string) int64 {
	t.Helper()
	out, err := f.s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID:        f.taskID,
		ExplorationID: f.expID,
		Worker:        "test",
		VulnClass:     vulnclass,
		Name:          vulnclass,
		Severity:      severity,
		Summary:       vulnclass + " summary",
		Evidence:      "poc",
	}, nil)
	if err != nil {
		t.Fatalf("failed to record the vulnerability: %v", err)
	}
	return out.FindingID
}

// channel reads the channel config back (for calling stepX per channel).
func (f *notifyFixture) channel(t *testing.T, id int64) *db.NotificationChannel {
	t.Helper()
	ch, err := f.pg.NotificationChannelByID(context.Background(), id)
	if err != nil {
		t.Fatalf("failed to read the channel: %v", err)
	}
	return ch
}

// deliver dispatches events and runs one delivery round for the given channel only.
func (f *notifyFixture) deliver(t *testing.T, chID int64, baseURL string) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	f.n.stepRealtime(ctx, f.channel(t, chID), 50, baseURL)
}

// createChannel creates a channel via the HTTP API, also covering the API's own validation path.
func (f *notifyFixture) createChannel(t *testing.T, payload map[string]any) int64 {
	t.Helper()
	raw, _ := json.Marshal(payload)
	r := f.request("POST", "/api/notify/channels", string(raw))
	if r.Code != 200 {
		t.Fatalf("failed to create channel %d: %s", r.Code, r.Body)
	}
	var res struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &res); err != nil || res.ID == 0 {
		t.Fatalf("create channel returned something unexpected: %s (%v)", r.Body, err)
	}
	t.Cleanup(func() { f.pg.Exec(`DELETE FROM notification_channels WHERE id=$1`, res.ID) })
	return res.ID
}

// fakeWebhook is a fake receiver that records the request bodies it gets.
type fakeWebhook struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []map[string]any
}

func newFakeWebhook(t *testing.T) *fakeWebhook {
	t.Helper()
	f := &fakeWebhook{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeWebhook) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeWebhook) body(t *testing.T, i int) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.bodies) {
		t.Fatalf("the fake receiver only got %d requests, cannot fetch request %d", len(f.bodies), i)
	}
	return f.bodies[i]
}

func (f *fakeWebhook) last(t *testing.T) map[string]any {
	t.Helper()
	if f.count() == 0 {
		t.Fatal("the fake receiver got no request at all")
	}
	return f.body(t, f.count()-1)
}

// markdownText takes the body out of the request, handling the field-name differences between providers:
// DingTalk markdown uses `text`, ActionCard uses `text`, WeCom markdown uses `content`.
func markdownText(t *testing.T, body map[string]any) string {
	t.Helper()
	for _, key := range []string{"markdown", "actionCard"} {
		section, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"text", "content"} {
			if s, ok := section[field].(string); ok && s != "" {
				return s
			}
		}
	}
	t.Fatalf("no recognisable body in the request: %v", body)
	return ""
}

// agePendingBatch ages this channel's not-yet-sent deliveries, for testing a digest batch becoming due.
func (f *notifyFixture) agePendingBatch(t *testing.T, chID int64) {
	t.Helper()
	if _, err := f.pg.Exec(`UPDATE notification_deliveries SET created_at = now() - interval '2 hours'
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyEndToEndRealtimeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "realtime",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	f.record(t, "SQL injection", "high")
	f.deliver(t, chID, "")

	if hook.count() != 1 {
		t.Fatalf("should send 1 message, actually %d", hook.count())
	}
	text := markdownText(t, hook.last(t))
	for _, want := range []string{"SQL injection", "High", "summary"} {
		if !strings.Contains(text, want) {
			t.Fatalf("message body is missing %q:\n%s", want, text)
		}
	}
	// the delivery should transition to sent.
	var pending int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state <> $2`,
		chID, db.NotifyStateSent).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("after delivery %d are still not marked sent", pending)
	}
}

func TestNotifyChannelAPIMasksSecretsAndPreservesOnUpdate(t *testing.T) {
	f := newNotifyFixture(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "masking case",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "https://oapi.dingtalk.com/robot/send?access_token=abc123456", "secret": "SECabcdef123456"},
	})

	r := f.request("GET", "/api/notify/channels", "")
	if r.Code != 200 {
		t.Fatalf("failed to list channels %d: %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), "abc123456") || strings.Contains(r.Body.String(), "SECabcdef123456") {
		t.Fatalf("the API echo leaked a credential: %s", r.Body)
	}
	var listed struct {
		Channels []struct {
			ID         int64          `json:"id"`
			Config     map[string]any `json:"config"`
			SecretKeys []string       `json:"secret_keys"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	var mine *struct {
		ID         int64          `json:"id"`
		Config     map[string]any `json:"config"`
		SecretKeys []string       `json:"secret_keys"`
	}
	for i := range listed.Channels {
		if listed.Channels[i].ID == chID {
			mine = &listed.Channels[i]
		}
	}
	if mine == nil {
		t.Fatal("the newly created channel did not appear in the list")
	}
	if !notify.IsMasked(fmt.Sprint(mine.Config["webhook"])) || !notify.IsMasked(fmt.Sprint(mine.Config["secret"])) {
		t.Fatalf("credential fields should be mask values: %v", mine.Config)
	}
	if len(mine.SecretKeys) == 0 {
		t.Fatal("the API should tell the frontend which fields are credentials")
	}

	// PATCH changing only the name + sending the mask credential back: the real credential must be kept as is.
	body, _ := json.Marshal(map[string]any{
		"name":   "after rename",
		"config": map[string]any{"webhook": fmt.Sprint(mine.Config["webhook"]), "secret": fmt.Sprint(mine.Config["secret"])},
	})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("update failed %d: %s", r.Code, r.Body)
	}
	cfg := f.channelConfig(t, chID)
	if cfg["webhook"] != "https://oapi.dingtalk.com/robot/send?access_token=abc123456" {
		t.Fatalf("the mask echo overwrote the real credential: %v", cfg["webhook"])
	}
	if cfg["secret"] != "SECabcdef123456" {
		t.Fatalf("the mask echo overwrote the secret: %v", cfg["secret"])
	}
	if f.channel(t, chID).Name != "after rename" {
		t.Fatal("the name was not updated")
	}

	// explicitly clearing secret should take effect (as distinct from "mask echo = keep unchanged").
	body, _ = json.Marshal(map[string]any{"config": map[string]any{"secret": ""}})
	if r := f.request("PATCH", fmt.Sprintf("/api/notify/channels/%d", chID), string(body)); r.Code != 200 {
		t.Fatalf("failed to clear secret %d: %s", r.Code, r.Body)
	}
	if _, still := f.channelConfig(t, chID)["secret"]; still {
		t.Fatal("an empty string should clear secret")
	}
}

func (f *notifyFixture) channelConfig(t *testing.T, id int64) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(f.channel(t, id).Config, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestNotifyChannelAPICreateValidation(t *testing.T) {
	f := newNotifyFixture(t)
	cases := []struct {
		name    string
		payload map[string]any
		wantSub string
	}{
		{"invalid type", map[string]any{"name": "x", "kind": "nope", "config": map[string]any{}}, "invalid channel type"},
		{"missing name", map[string]any{"kind": notify.KindDingTalk, "config": map[string]any{"webhook": "https://e.com/h"}}, "missing channel name"},
		{"missing webhook", map[string]any{"name": "x", "kind": notify.KindDingTalk, "config": map[string]any{}}, "webhook"},
		{"invalid webhook scheme", map[string]any{"name": "x", "kind": notify.KindDingTalk, "config": map[string]any{"webhook": "file:///etc/passwd"}}, "invalid webhook URL"},
		{"invalid mode", map[string]any{"name": "x", "kind": notify.KindDingTalk, "mode": "sometimes", "config": map[string]any{"webhook": "https://e.com/h"}}, "invalid notification mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			r := f.request("POST", "/api/notify/channels", string(raw))
			if r.Code != 400 {
				t.Fatalf("should return 400, got %d: %s", r.Code, r.Body)
			}
			if !strings.Contains(r.Body.String(), tc.wantSub) {
				t.Fatalf("the error message should mention %q, got %s", tc.wantSub, r.Body)
			}
		})
	}
	if r := f.request("DELETE", "/api/notify/channels/99999999", ""); r.Code != 404 {
		t.Fatalf("deleting a non-existent channel should 404, got %d", r.Code)
	}
}

func TestNotifyFilterBlocksBelowThreshold(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "critical only",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
		"filter": map[string]any{"min_severity": "critical"},
	})
	f.record(t, "low-severity issue", "low")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a vulnerability below the threshold should produce no delivery, got %d", n)
	}
	f.n.stepRealtime(context.Background(), f.channel(t, chID), 50, "")
	if hook.count() != 0 {
		t.Fatal("a filtered vulnerability should send no message")
	}
}

func TestNotifyDigestBatchesMultipleFindingsIntoOneMessage(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "digest",
		"kind":   notify.KindDingTalk,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"webhook": hook.URL},
	})
	for i := 0; i < 3; i++ {
		f.record(t, fmt.Sprintf("digest vuln %d", i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)

	// not due: no send.
	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 0 {
		t.Fatal("the digest batch was sent before it was due")
	}

	// after ageing the batch: three merge into one message.
	f.agePendingBatch(t, chID)
	f.n.stepDigest(ctx, ch, 50, "")
	if got := hook.count(); got != 1 {
		t.Fatalf("three should merge into one message, actually sent %d", got)
	}
	text := markdownText(t, hook.last(t))
	if !strings.Contains(text, "in the last") || !strings.Contains(text, "3 new vulnerabilities") {
		t.Fatalf("the digest message is missing the count/time-window text:\n%s", text)
	}
	for i := 1; i <= 3; i++ {
		if !strings.Contains(text, fmt.Sprintf("digest vuln %d", i)) {
			t.Fatalf("the digest message is missing item %d:\n%s", i, text)
		}
	}
	// the same batch should share batch_id.
	var distinct, total int
	if err := f.pg.QueryRow(`SELECT count(DISTINCT batch_id), count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&distinct, &total); err != nil {
		t.Fatal(err)
	}
	if total != 3 || distinct != 1 {
		t.Fatalf("the three deliveries should share one batch_id, got distinct=%d total=%d", distinct, total)
	}
}

func TestNotifyDisabledChannelDoesNotSend(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":    "disabled channel",
		"kind":    notify.KindDingTalk,
		"enabled": false,
		"config":  map[string]any{"webhook": hook.URL},
	})
	f.record(t, "a vulnerability during disablement", "critical")
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a disabled channel should produce no delivery, got %d", n)
	}
}

func TestNotifyStatusChangeDelivery(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "status-change subscription",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
		"filter": map[string]any{"on_status_change": true},
	})
	finding := f.record(t, "status-change case", "high")
	r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"fixed"}`)
	if r.Code != 200 {
		t.Fatalf("failed to change status %d: %s", r.Code, r.Body)
	}
	f.deliver(t, chID, "")

	// there should be two: the fixed one is the status change; the finding_created one may also be sent in the same round.
	// the status change is actually created later, but it does not depend on order, so search them all.
	found := false
	for i := 0; i < hook.count(); i++ {
		text := markdownText(t, hook.body(t, i))
		if strings.Contains(text, "Status change") && strings.Contains(text, "Fixed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not receive a message containing \"Status change → Fixed\" (%d in total)", hook.count())
	}
}

func TestNotifyStatusChangeSuppressedByDefault(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "not subscribed to status changes",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	finding := f.record(t, "not subscribed to changes", "high")
	if r := f.request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", finding), `{"status":"false_positive"}`); r.Code != 200 {
		t.Fatalf("failed to change status %d: %s", r.Code, r.Body)
	}
	if _, _, err := f.pg.FanOutPendingEvents(context.Background(), 500); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries d
JOIN notification_events e ON e.id = d.event_id
WHERE d.channel_id=$1 AND e.kind=$2`, chID, notify.EventFindingStatusChanged).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a channel not subscribed to status changes should receive no status-change delivery, got %d", n)
	}
}

func TestNotifyTestMessageEndpoint(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "test send",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", chID), ""); r.Code != 200 {
		t.Fatalf("test send failed %d: %s", r.Code, r.Body)
	}
	if hook.count() != 1 {
		t.Fatalf("the fake receiver should get 1 test message, got %d", hook.count())
	}
	// the test message must be obviously a test, not mistakable for a real vulnerability.
	if text := markdownText(t, hook.last(t)); !strings.Contains(text, "test") {
		t.Fatalf("the test message should be marked as a test: %s", text)
	}
	// on a broken config, pass the channel's raw error faithfully back to the user.
	badID := f.createChannel(t, map[string]any{
		"name":   "bad address",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "http://127.0.0.1:1/hook"},
	})
	if r := f.request("POST", fmt.Sprintf("/api/notify/channels/%d/test", badID), ""); r.Code != 502 {
		t.Fatalf("a failed delivery should return 502, got %d: %s", r.Code, r.Body)
	}
}

func TestNotifyDeliveriesHistoryAndRetry(t *testing.T) {
	f := newNotifyFixture(t)
	// point at an address bound to fail, to produce a failed delivery.
	chID := f.createChannel(t, map[string]any{
		"name":   "failure retry",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": "http://127.0.0.1:1/hook"},
	})
	f.record(t, "a notification that will fail", "high")
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	ch := f.channel(t, chID)
	// deliver repeatedly until the retry budget is exhausted.
	for i := 0; i < db.MaxNotifyAttempts; i++ {
		f.n.stepRealtime(ctx, ch, 50, "")
		if _, err := f.pg.Exec(`UPDATE notification_deliveries SET next_attempt_at = now() - interval '1 minute' WHERE channel_id=$1`, chID); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	if err := f.pg.QueryRow(`SELECT state FROM notification_deliveries WHERE channel_id=$1`, chID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStateFailed {
		t.Fatalf("after retries are exhausted it should be failed, got %s", state)
	}

	r := f.request("GET", fmt.Sprintf("/api/notify/deliveries?channel_id=%d&state=failed", chID), "")
	if r.Code != 200 {
		t.Fatalf("failed to query history %d: %s", r.Code, r.Body)
	}
	var hist struct {
		Deliveries []struct {
			ID        int64  `json:"id"`
			State     string `json:"state"`
			LastError string `json:"last_error"`
			Attempts  int    `json:"attempts"`
			Title     string `json:"title"`
		} `json:"deliveries"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Total != 1 || len(hist.Deliveries) != 1 {
		t.Fatalf("should find 1 failed delivery, got total=%d len=%d", hist.Total, len(hist.Deliveries))
	}
	if hist.Deliveries[0].LastError == "" {
		t.Fatal("the history should carry the failure reason, otherwise the user cannot diagnose it")
	}
	if hist.Deliveries[0].Attempts < db.MaxNotifyAttempts {
		t.Fatalf("the attempt count should be recorded, got %d", hist.Deliveries[0].Attempts)
	}
	if hist.Deliveries[0].Title != "a notification that will fail" {
		t.Fatalf("the history should carry the vulnerability title, got %q", hist.Deliveries[0].Title)
	}

	// manual resend: should go back to pending with the count zeroed.
	if r := f.request("POST", fmt.Sprintf("/api/notify/deliveries/%d/retry", hist.Deliveries[0].ID), ""); r.Code != 200 {
		t.Fatalf("resend failed %d: %s", r.Code, r.Body)
	}
	var attempts int
	if err := f.pg.QueryRow(`SELECT state, attempts FROM notification_deliveries WHERE id=$1`, hist.Deliveries[0].ID).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != db.NotifyStatePending || attempts != 0 {
		t.Fatalf("after a resend it should be pending with attempts=0, got %s/%d", state, attempts)
	}
}

func TestNotifyMetaAndSettingsRoundTrip(t *testing.T) {
	f := newNotifyFixture(t)
	r := f.request("GET", "/api/notify/meta", "")
	if r.Code != 200 {
		t.Fatalf("meta failed: %s", r.Body)
	}
	var meta struct {
		Kinds []struct {
			Kind       string   `json:"kind"`
			SecretKeys []string `json:"secret_keys"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Kinds) != len(notify.Kinds()) {
		t.Fatalf("meta should list all %d channels, got %d", len(notify.Kinds()), len(meta.Kinds))
	}
	for _, k := range meta.Kinds {
		if len(k.SecretKeys) == 0 {
			t.Errorf("channel %s did not report its credential fields", k.Kind)
		}
	}

	// the three global settings round-trip. A trailing slash should be normalised away, otherwise the link-back would build "//function/...".
	if r := f.request("PUT", "/api/settings", `{"notify_public_base_url":"https://artex.example.com/","notify_digest_interval_min":15,"notify_enabled":true}`); r.Code != 200 {
		t.Fatalf("failed to write settings %d: %s", r.Code, r.Body)
	}
	t.Cleanup(func() {
		f.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2)`, settingNotifyPublicBaseURL, settingNotifyDigestMinutes)
	})
	payload := f.s.settingsPayload()
	if payload["notify_public_base_url"] != "https://artex.example.com" {
		t.Fatalf("the link-back address was not normalised: %v", payload["notify_public_base_url"])
	}
	if payload["notify_digest_interval_min"] != 15 {
		t.Fatalf("the digest window did not take effect: %v", payload["notify_digest_interval_min"])
	}

	// invalid values should be rejected.
	for _, body := range []string{
		`{"notify_public_base_url":"ftp://x"}`,
		`{"notify_digest_interval_min":0}`,
		`{"notify_digest_interval_min":99999}`,
	} {
		if r := f.request("PUT", "/api/settings", body); r.Code != 400 {
			t.Errorf("%s should return 400, got %d", body, r.Code)
		}
	}
}

// TestNotifyDeepLinkUsesPublicBaseURL covers the link-back building: when public_base_url is set
// a single message must use a button ActionCard, with the link pointing at the vulnerability detail page.
func TestNotifyDeepLinkUsesPublicBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "link-back",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	finding := f.record(t, "a vulnerability with a link-back", "high")
	f.deliver(t, chID, "https://artex.example.com")

	body := hook.last(t)
	card, _ := body["actionCard"].(map[string]any)
	if card == nil {
		t.Fatalf("with a link-back it should use an ActionCard, got msgtype=%v", body["msgtype"])
	}
	want := fmt.Sprintf("https://artex.example.com/function/findings/detail?id=%d", finding)
	if card["singleURL"] != want {
		t.Fatalf("link-back wrong\nwant %s\ngot %v", want, card["singleURL"])
	}
}

// TestNotifyNoDeepLinkWithoutBaseURL covers the reverse: with no external address set it should not produce a bad link
// (e.g. pointing at localhost or a relative path), and should fall back to plain markdown.
func TestNotifyNoDeepLinkWithoutBaseURL(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	chID := f.createChannel(t, map[string]any{
		"name":   "no link-back",
		"kind":   notify.KindDingTalk,
		"config": map[string]any{"webhook": hook.URL},
	})
	f.record(t, "a vulnerability with no link-back", "high")
	f.deliver(t, chID, "")

	body := hook.last(t)
	if body["msgtype"] != "markdown" {
		t.Fatalf("with no external address set it should send markdown, got %v", body["msgtype"])
	}
	if text := markdownText(t, body); strings.Contains(text, "View details") {
		t.Fatalf("with no external address set there should be no detail link:\n%s", text)
	}
}

// TestNotifyDigestSegmentsAndDefersRemainder is the end-to-end evidence for the "silent loss" fix.
//
// a digest message is bound by the channel length limit (WeCom's 4096 bytes), and when a batch does not fit it must be split **by whole item**:
// the ones that fit into this message are marked delivered, the rest go back into the queue for the next message. The old implementation marked the whole batch
// successful — the truncated ones were neither in the message nor in the failure list, and the delivery history still showed success,
// and the vulnerabilities were simply lost.
//
// assert four things: ① only the number actually fitted is marked ② the rest are still not-yet-sent ③ the deferred items
// **did not consume a retry attempt** ④ running another round sends the rest (it does not get stuck).
func TestNotifyDigestSegmentsAndDefersRemainder(t *testing.T) {
	f := newNotifyFixture(t)
	hook := newFakeWebhook(t)
	// use WeCom: a 4096-byte markdown limit, the tightest of the six channels.
	chID := f.createChannel(t, map[string]any{
		"name":   "segmented digest",
		"kind":   notify.KindWeCom,
		"mode":   db.NotifyModeDigest,
		"config": map[string]any{"webhook": hook.URL},
	})
	const total = 60
	// make the title long, so 60 items far exceed 4096 bytes and must be segmented.
	longName := strings.Repeat("an overly long vulnerability name", 6)
	for i := 0; i < total; i++ {
		f.record(t, longName+strconv.Itoa(i+1), "high")
	}
	ctx := context.Background()
	if _, _, err := f.pg.FanOutPendingEvents(ctx, 500); err != nil {
		t.Fatal(err)
	}
	f.agePendingBatch(t, chID)
	ch := f.channel(t, chID)

	f.n.stepDigest(ctx, ch, 50, "")
	if hook.count() != 1 {
		t.Fatalf("should send one message, got %d", hook.count())
	}

	var sent, pending int
	if err := f.pg.QueryRow(`SELECT
    count(*) FILTER (WHERE state=$2),
    count(*) FILTER (WHERE state=$3)
  FROM notification_deliveries WHERE channel_id=$1`, chID, db.NotifyStateSent, db.NotifyStatePending).
		Scan(&sent, &pending); err != nil {
		t.Fatal(err)
	}
	if sent == 0 {
		t.Fatal("some items should be marked delivered")
	}
	if pending == 0 {
		t.Fatalf("a batch of %d could not all fit in 4096 bytes, there should be some not-yet-sent; sent=%d", total, sent)
	}
	if sent+pending != total {
		t.Fatalf("the item counts do not add up: sent=%d pending=%d total=%d (neither delivered nor not-yet-sent = lost)", sent, pending, total)
	}
	// the message body must truthfully say how many more are not included in this one.
	if text := markdownText(t, hook.last(t)); !strings.Contains(text, "remaining") {
		t.Fatalf("the message should say more items are not included in this one:\n%.400s", text)
	}

	// a deferred item must not consume the retry budget: attempts was optimistically +1 at claim time, and must be subtracted back on defer.
	var maxAttempts int
	if err := f.pg.QueryRow(`SELECT COALESCE(max(attempts),0) FROM notification_deliveries
WHERE channel_id=$1 AND state=$2`, chID, db.NotifyStatePending).Scan(&maxAttempts); err != nil {
		t.Fatal(err)
	}
	if maxAttempts > 0 {
		t.Fatalf("a deferred item should not consume a retry attempt (otherwise it would be judged failed after a few), got attempts=%d", maxAttempts)
	}

	// run repeatedly until it converges. The assertion is that **everything is eventually delivered** and it really took several rounds —
	// this is stronger than "sent on the second round": it proves segmentation neither gets stuck nor loses the remaining items.
	rounds := 0
	for {
		var undelivered int
		if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries
WHERE channel_id=$1 AND state <> $2 AND state <> $3`, chID, db.NotifyStateSent, db.NotifyStateFailed).
			Scan(&undelivered); err != nil {
			t.Fatal(err)
		}
		if undelivered == 0 {
			break
		}
		rounds++
		if rounds > total+5 {
			t.Fatalf("segmented delivery does not converge: ran %d rounds with %d still pending", rounds, undelivered)
		}
		before := hook.count()
		f.n.stepDigest(ctx, ch, 50, "")
		if hook.count() == before {
			t.Fatalf("round %d made no progress, the remaining %d would be stuck forever", rounds, undelivered)
		}
	}
	if rounds < 2 {
		t.Fatalf("a 4096-byte message cannot fit %d long-title vulnerabilities and should be sent over several rounds, actually took %d", total, rounds)
	}
	// every round after the first should be a **pure continuation**, with no items rejected by the channel.
	var failed int
	if err := f.pg.QueryRow(`SELECT count(*) FROM notification_deliveries WHERE channel_id=$1 AND state=$2`,
		chID, db.NotifyStateFailed).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Fatalf("the fake receiver always returns success, so there should be no failed items, got %d", failed)
	}
}

// TestNotifyBackoffTableMatchesAttemptBudget is an anti-drift assertion.
//
// the retry budget (db.MaxNotifyAttempts) and the backoff sequence table (notifyBackoff) live in two packages:
// the former is the state machine's policy, the latter the engine's execution cadence. If only one is changed — say the budget raised to 5
// but a backoff tier forgotten — the code does not error, it just makes the 4th and 5th retries reuse the last tier's interval,
// showing as "the retry cadence mysteriously slows down", hard to trace back to here when diagnosing.
// asserting the two lengths match exposes this drift in CI.
func TestNotifyBackoffTableMatchesAttemptBudget(t *testing.T) {
	if len(notifyBackoff) != db.MaxNotifyAttempts {
		t.Fatalf("the number of backoff tiers (%d) does not match the max attempts (%d) — changing one means changing the other",
			len(notifyBackoff), db.MaxNotifyAttempts)
	}
	// the backoff intervals must be monotonically non-decreasing, otherwise retries get more eager and worsen rate limiting.
	for i := 1; i < len(notifyBackoff); i++ {
		if notifyBackoff[i] < notifyBackoff[i-1] {
			t.Fatalf("backoff intervals must be monotonically non-decreasing: tier %d %v < tier %d %v",
				i, notifyBackoff[i], i-1, notifyBackoff[i-1])
		}
	}
}

// TestNotifyRateLimitDoesNotConsumeRetryBudget locks in the "take tokens first, then claim" order.
// if reversed (claim first, drop later), a delivery held off by rate limiting has already counted one attempt,
// and the budget would be burned by pure waiting, finally landing in failed.
func TestNotifyRateLimitDoesNotConsumeRetryBudget(t *testing.T) {
	// only tests the token bucket itself, no Server needed (and one should not be built for it).
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// 1 per minute: at most 1 with a full bucket.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now); got != 1 {
		t.Fatalf("with a full bucket at 1 per minute it should take 1 token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("once tokens are exhausted it should return 0 immediately, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(30*time.Second)); got != 0 {
		t.Fatalf("half way should not refill a whole token, got %d", got)
	}
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Minute)); got != 1 {
		t.Fatalf("a full window should refill 1 token, got %d", got)
	}
	// a no-rate-limit channel uses a finite cap, to avoid a single round being dragged by an unbounded backlog.
	if got := n.takeTokens(2, 0, notifyUnlimitedBurstPerTick+10, now); got != notifyUnlimitedBurstPerTick {
		t.Fatalf("no rate limit should return the per-round cap %d, got %d", notifyUnlimitedBurstPerTick, got)
	}
	// the token buckets of different channels are independent of each other.
	if got := n.takeTokens(1, 1, notifyMaxSendsPerChannelPerTick, now.Add(time.Millisecond)); got != 0 {
		t.Fatalf("channel 1's bucket should still be empty, got %d", got)
	}
}

// TestNotifyTakeTokensKeepsUnusedTokens locks in the "take only want" semantics.
//
// the old implementation drained the whole bucket and let the caller truncate, so a rate=100/min channel with a full bucket
// used 5 in one round and discarded the other 95 tokens; a channel with no deliveries that round was likewise charged.
// the result was that the comment's claim of "can burst rate_per_min when backlogged" was never achievable in any situation.
func TestNotifyTakeTokensKeepsUnusedTokens(t *testing.T) {
	n := &Notifier{buckets: map[int64]*notifyBucket{}}
	now := time.Now()
	// the bucket starts full (100), and this round wants only 5.
	if got := n.takeTokens(1, 100, 5, now); got != 5 {
		t.Fatalf("with want=5 it should take exactly 5 tokens, got %d", got)
	}
	// key assertion: the other 95 must still be in the bucket, not drained and discarded.
	// do not advance time, to ensure what is taken can only come from the stock, not a refill.
	if got := n.takeTokens(1, 100, 95, now); got != 95 {
		t.Fatalf("the remaining tokens should still be available (expected 95), got %d — the bucket was drained for the whole round", got)
	}
	if got := n.takeTokens(1, 100, 1, now); got != 0 {
		t.Fatalf("the bucket is drained, it should return 0, got %d", got)
	}
	// want<=0 should not deduct any token (an empty round is free).
	n2 := &Notifier{buckets: map[int64]*notifyBucket{}}
	if got := n2.takeTokens(1, 20, 0, now); got != 0 {
		t.Fatalf("want=0 should return 0, got %d", got)
	}
	if got := n2.takeTokens(1, 20, 20, now); got != 20 {
		t.Fatalf("the want=0 call should not consume a token, it should still take a full 20, got %d", got)
	}
}

// TestDigestTickPlanDecouplesBatchSizeFromSendBudget pins down the two dimensions of digest mode.
//
// once the digest batch size is tied to the per-round request budget, a rate_per_min=20 channel can only refill 1 token in each
// 3-second tick, so each digest message holds only 1 vulnerability — functionally no digest at all,
// while the message header still says "1 new vulnerability in the last 30 minutes". This degradation does not error,
// and the existing end-to-end cases cannot see it (they manually pass a large enough limit to stepDigest,
// bypassing the quota calculation in step), so the decision itself is asserted directly here.
func TestDigestTickPlanDecouplesBatchSizeFromSendBudget(t *testing.T) {
	tokens, claimLimit := digestTickPlan()
	// one batch = one message = one request = one token. The token's unit is messages, not vulnerabilities.
	if tokens != 1 {
		t.Fatalf("one digest batch sends one message and should consume exactly 1 token, got %d", tokens)
	}
	if claimLimit != db.MaxDigestBatchSize {
		t.Fatalf("the digest batch size should be the memory upper bound db.MaxDigestBatchSize=%d, got %d",
			db.MaxDigestBatchSize, claimLimit)
	}
	// key relationship: the batch size must be far larger than the per-round request budget. If the two are ever the same order of magnitude,
	// "how many messages to send" and "how many vulnerabilities a batch holds" have been merged into one number again.
	if claimLimit <= notifyMaxSendsPerChannelPerTick {
		t.Fatalf("the digest batch size %d should not be constrained by the per-round request budget %d — "+
			"the request budget is the \"how many requests to send\" derived from the lease, a different dimension from \"how many vulnerabilities a batch holds\"",
			claimLimit, notifyMaxSendsPerChannelPerTick)
	}
}

// TestNotifyTickBudgetFitsWithinLease is another anti-drift assertion.
//
// the per-round delivery cap for a single channel (notifyMaxSendsPerChannelPerTick) is derived backwards from the lease duration:
// the worst-case duration of serial delivery in one round must be < the lease, otherwise the last few are not sent when the lease expires,
// and in a multi-instance deployment the peer re-claims and resends them. These three constants live in different places,
// and changing any one may break the relationship with no error at all — so it is pinned here.
func TestNotifyTickBudgetFitsWithinLease(t *testing.T) {
	worst := time.Duration(notifyMaxSendsPerChannelPerTick) * notifySendTimeout
	if worst >= notifyLease {
		t.Fatalf("a single channel's worst-case duration in one round %v should not reach or exceed the lease %v "+
			"(notifyMaxSendsPerChannelPerTick=%d × notifySendTimeout=%v) — "+
			"changing any of these three constants requires checking the other two",
			worst, notifyLease, notifyMaxSendsPerChannelPerTick, notifySendTimeout)
	}
}
