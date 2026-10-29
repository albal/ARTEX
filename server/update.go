package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/Autumn-27/artex/selfupdate"
)

// the HTTP face of the web UI one-click update. The real download/verify/swap logic is all in the selfupdate package,
// this only handles the auth boundary, concurrency mutex, progress broadcast, and telling main "time to exit".
//
// the restart is not done by this process: after staging the new version the process exits with selfupdate.ExitRestart,
// and the supervisor script (start.sh / start.bat, the ENTRYPOINT under Docker) relaunches it.

// restartCh is closed when the upgrade is ready or the rollback is complete, and main exits with ExitRestart on receiving it.
var (
	restartOnce sync.Once
	restartCh   = make(chan struct{})
)

// RestartRequested returns a channel that is closed when "please exit and let the supervisor relaunch me".
func RestartRequested() <-chan struct{} { return restartCh }

func requestRestart() { restartOnce.Do(func() { close(restartCh) }) }

// bootState is the conclusion of selfupdate.Bootstrap at this start-up (upgrade succeeded / just rolled back /
// the staged file was discarded), injected by main, so /api/update/check can tell the frontend truthfully the fate of the last upgrade.
var (
	bootStateMu sync.Mutex
	bootState   selfupdate.State
)

// SetBootUpdateState is called once by main at start-up.
func SetBootUpdateState(st selfupdate.State) {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	bootState = st
}

func bootUpdateState() selfupdate.State {
	bootStateMu.Lock()
	defer bootStateMu.Unlock()
	return bootState
}

// releaseCache caches GitHub's latest-version query result.
//
// the top bar's "there is a new version" hint queries once on every full page load, and the unauthenticated GitHub API is
// 60 per IP per hour — without caching, opening a few more tabs or refreshing a few times would exhaust the quota,
// and then a real update would not be able to query. A user explicitly clicking "check for updates" can force past the cache.
type releaseCache struct {
	mu  sync.Mutex
	rel *selfupdate.Release
	err error
	at  time.Time
	// fetch is the data-fetching function, an injection point kept only for tests; when nil it goes to the real GitHub query.
	fetch func(context.Context, *http.Client) (*selfupdate.Release, error)
}

const (
	releaseTTL = 30 * time.Minute
	// a failure result is also cached for a short while, otherwise when GitHub is unreachable every page load would wait out a timeout;
	// but the TTL must be short, so it recovers on its own soon after the network is back.
	releaseErrTTL = 2 * time.Minute
	// the timeout used for the query. NewClient's 30-minute timeout is for downloading the whole package; a version check must not wait that long.
	releaseTimeout = 20 * time.Second
)

var relCache = &releaseCache{}

// get returns the latest Release, not hitting the network on a cache hit.
//
// the lock is held throughout the fetch: concurrent requests queue for the same query's result, rather than each hitting GitHub
// (several tabs querying at once right when the page loads is exactly the moment most likely to trip rate limiting).
func (c *releaseCache) get(ctx context.Context, client *http.Client, force bool) (*selfupdate.Release, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force {
		ttl := releaseTTL
		if c.err != nil {
			ttl = releaseErrTTL
		}
		if !c.at.IsZero() && time.Since(c.at) < ttl {
			return c.rel, c.err
		}
	}

	fetch := c.fetch
	if fetch == nil {
		fetch = selfupdate.FetchLatest
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	rel, err := fetch(ctx, client)
	// a cancelled request (the user closed the tab) does not mean GitHub has a problem, so do not write it into the cache,
	// otherwise the next visitor would get a baffling "cancelled" error.
	if err != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return c.rel, err
	}
	c.rel, c.err, c.at = rel, err, time.Now()
	return rel, err
}

// updateProgress is one progress event pushed to the frontend.
type updateProgress struct {
	Phase   selfupdate.Phase `json:"phase"`
	Percent int              `json:"percent"` // only meaningful during the download stage; -1 otherwise
	Message string           `json:"message"`
	Version string           `json:"version,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// updateHub holds one upgrade's progress and broadcasts it to SSE subscribers.
//
// running doubles as a mutex: a second POST /api/update/apply during an upgrade gets a 409 directly,
// to avoid two goroutines writing to the same artex.new at once.
type updateHub struct {
	mu      sync.Mutex
	running bool
	cur     updateProgress
	subs    map[chan updateProgress]struct{}
}

var updHub = &updateHub{
	cur:  updateProgress{Phase: selfupdate.PhaseIdle, Percent: -1},
	subs: map[chan updateProgress]struct{}{},
}

// begin claims the upgrade permission, returning false if one is already in progress.
func (h *updateHub) begin(version string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return false
	}
	h.running = true
	h.cur = updateProgress{Phase: selfupdate.PhaseDownload, Percent: 0, Message: "preparing…", Version: version}
	h.fanout(h.cur)
	return true
}

// finish ends an upgrade. err nil means staging succeeded and it is waiting to restart.
func (h *updateHub) finish(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	if err != nil {
		h.cur = updateProgress{Phase: selfupdate.PhaseFailed, Percent: -1, Message: "update failed", Error: err.Error(), Version: h.cur.Version}
	} else {
		h.cur = updateProgress{Phase: selfupdate.PhaseStaged, Percent: 100, Message: "the new version is ready, restarting…", Version: h.cur.Version}
	}
	h.fanout(h.cur)
}

func (h *updateHub) publish(ph selfupdate.Phase, pct int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = updateProgress{Phase: ph, Percent: pct, Message: msg, Version: h.cur.Version}
	h.fanout(h.cur)
}

// fanout must be called while holding h.mu. Subscriber channels are buffered, and when full the event is dropped —
// progress is discardable transient information and must never let a stuck SSE connection block the upgrade itself.
func (h *updateHub) fanout(p updateProgress) {
	for ch := range h.subs {
		select {
		case ch <- p:
		default:
		}
	}
}

func (h *updateHub) snapshot() (updateProgress, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.running
}

func (h *updateHub) subscribe() (<-chan updateProgress, func()) {
	ch := make(chan updateProgress, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// updateCheck queries the latest release on GitHub and compares it with the current version.
//
// the frontend also connects to api.github.com directly (GitHub's CORS is *), but **this endpoint is authoritative**:
// the download is done by the backend, and an update only makes sense if the backend can reach GitHub. The browser reaching it while the server cannot
// is common (the server is on an internal network, or the proxy is only configured in the browser), in which case an update would inevitably fail,
// so it is better to report the error truthfully at this check step.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion
	mode := "binary"
	if selfupdate.InDocker() {
		mode = "docker"
	}
	boot := bootUpdateState()
	out := map[string]any{
		"current":     current,
		"mode":        mode,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"has_backup":  selfupdate.HasBackup(),
		"repo":        selfupdate.Repo,
		"boot_notice": boot.Detail,
		"rolled_back": boot.RolledBack,
	}

	// the top bar hint uses the cache (default); a user clicking "check for updates" passes force=1 to force a fresh lookup.
	force := r.URL.Query().Get("force") != ""
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, force)
	if err != nil {
		out["error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}

	latest := rel.TagName
	out["latest"] = latest
	out["notes"] = rel.Body
	out["html_url"] = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		out["published_at"] = rel.PublishedAt.Format(time.RFC3339)
	}

	asset := selfupdate.AssetName(latest, runtime.GOOS, runtime.GOARCH)
	out["asset"] = asset
	if a, ok := rel.FindAsset(asset); ok {
		out["asset_available"] = true
		out["size"] = a.Size
	} else {
		out["asset_available"] = false
	}

	cmp, comparable := selfupdate.CompareVersions(current, latest)
	out["comparable"] = comparable
	out["has_update"] = comparable && cmp < 0
	if !comparable {
		// a development build (dev / git describe with a suffix) has no comparable version number. Allowing it would only
		// overwrite the binary being debugged locally with a release, so updating is simply refused.
		out["reason"] = fmt.Sprintf("the current version %q is not a formal release, one-click update is disabled", current)
	}
	writeJSON(w, 200, out)
}

// updateApply downloads and stages the new version, then lets the process exit for the supervisor to restart.
//
// returns 202 immediately, with the real work running on a background goroutine: downloading the whole package may take minutes,
// and hanging it on the request would get it cut off by a reverse-proxy timeout. Progress goes through /api/update/stream.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request) {
	current := BuildVersion

	// use the cache: to ensure what is installed is the version the user saw and confirmed on the interface.
	client := selfupdate.NewClient(s.m.GlobalProxy())
	rel, err := relCache.get(r.Context(), client, false)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	cmp, comparable := selfupdate.CompareVersions(current, rel.TagName)
	if !comparable {
		writeErr(w, 400, fmt.Sprintf("the current version %q is not a formal release, one-click update is disabled", current))
		return
	}
	if cmp >= 0 {
		writeErr(w, 400, fmt.Sprintf("already on the latest version %s", current))
		return
	}
	if !updHub.begin(rel.TagName) {
		writeErr(w, 409, "an update is already in progress")
		return
	}

	go func() {
		// deliberately use s.ctx rather than the request's ctx: the request ends once the HTTP response returns,
		// and hanging the download on it would cancel it immediately.
		err := selfupdate.Stage(s.ctx, client, rel, current, func(ph selfupdate.Phase, pct int, msg string) {
			updHub.publish(ph, pct, msg)
		})
		updHub.finish(err)
		if err != nil {
			log.Printf("[update] update failed: %v", err)
			return
		}
		log.Printf("[update] %s → %s staged, about to exit to complete the swap", current, rel.TagName)
		// leave a little time to push the last progress to the frontend, then trigger the exit.
		time.Sleep(1500 * time.Millisecond)
		requestRestart()
	}()

	writeJSON(w, 202, map[string]any{"ok": true, "target": rel.TagName})
}

// updateRollback actively goes back to the previous version (artex.old backed up before the swap).
func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request) {
	if _, running := updHub.snapshot(); running {
		writeErr(w, 409, "an update is in progress, cannot roll back")
		return
	}
	if err := selfupdate.Rollback(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[update] manually rolled back to the previous version, about to exit to complete the switch")
	writeJSON(w, 202, map[string]any{"ok": true})
	go func() {
		time.Sleep(500 * time.Millisecond)
		requestRestart()
	}()
}

// updateStream pushes update progress via SSE.
func (s *Server) updateStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := updHub.subscribe()
	defer unsub()

	send := func(p updateProgress) {
		b, _ := json.Marshal(p)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	// send the current state first, so a page refresh immediately shows an in-progress upgrade.
	cur, _ := updHub.snapshot()
	send(cur)

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			send(p)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
