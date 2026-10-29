package db

import (
	"encoding/json"
	"time"
)

// LLM retry policy: the global configuration of "count + interval" for the five retry layers, see docs/llm-retry-design.md.
// It lives in one JSON value in the settings table — it is one set of runtime parameters per machine, not worth its own table;
// reads fall back to the built-in defaults, so when the key is absent (a brand-new database/never configured) the behaviour is exactly as in the hard-coded-constant era.

const settingLLMRetryPolicy = "llm_retry_policy"

// RetryRule is one layer's knob pair. The zero value means "unset":
//
//	Attempts   0 = use the built-in default count; -1 = disable this layer's retry; >0 = use this value
//	IntervalMS 0 = use this layer's own interval strategy (usually exponential backoff); >0 = use a fixed interval in milliseconds instead
//
// -1 is "explicitly off" rather than "0 times", because 0 is already taken by "not configured".
type RetryRule struct {
	Attempts   int `json:"attempts"`
	IntervalMS int `json:"interval_ms"`
}

// Interval returns the configured fixed interval, or 0 when unset (caller keeps
// its own default ladder).
func (r RetryRule) Interval() time.Duration {
	if r.IntervalMS <= 0 {
		return 0
	}
	return time.Duration(r.IntervalMS) * time.Millisecond
}

// Or returns the rule with each unset field filled in from fallback. Used to
// layer a profile override on top of the global policy field by field, so a
// profile that only pins the interval still inherits the global count.
func (r RetryRule) Or(fallback RetryRule) RetryRule {
	if r.Attempts == 0 {
		r.Attempts = fallback.Attempts
	}
	if r.IntervalMS == 0 {
		r.IntervalMS = fallback.IntervalMS
	}
	return r
}

// retry knob bounds. A count above the cap turns a blip into a token bonfire;
// an interval above an hour outlives any transient failure worth waiting out.
const (
	maxRetryAttempts   = 20
	maxRetryIntervalMS = 3600_000 // 1h
)

// Clamped returns the rule with out-of-range values pulled back into the sane
// band (attempts within [-1, 20], interval within [0, 1h]).
func (r RetryRule) Clamped() RetryRule {
	if r.Attempts < -1 {
		r.Attempts = -1
	}
	if r.Attempts > maxRetryAttempts {
		r.Attempts = maxRetryAttempts
	}
	if r.IntervalMS < 0 {
		r.IntervalMS = 0
	}
	if r.IntervalMS > maxRetryIntervalMS {
		r.IntervalMS = maxRetryIntervalMS
	}
	return r
}

// Clamped bounds a profile's override the same way the global policy is bounded,
// so a hand-crafted API payload can't land a value the CHECK constraint rejects.
func (o RetryOverride) Clamped() RetryOverride {
	o.Connect, o.Empty, o.Stream = o.Connect.Clamped(), o.Empty.Clamped(), o.Stream.Clamped()
	return o
}

// LLMRetryPolicy holds the five-layer retry configuration. Connect/Empty/Stream are the
// per-request layers (a profile may override them, see LLMProfile.Retry);
// Breaker and Intent are process-wide by nature and live only here.
type LLMRetryPolicy struct {
	// Connect: SDK connect retry (connection reset/timeout/429/5xx, before the stream starts). Default 3 attempts, exponential backoff.
	Connect RetryRule `json:"connect"`
	// Empty: SDK empty-response retry (completed but with no content block, openai format only). Default 2 attempts, exponential backoff.
	Empty RetryRule `json:"empty"`
	// Stream: same-provider safe-window retry (replaying a dropped stream before any output was delivered). Default 2 attempts, exponential from 0.5s (capped at 4s).
	Stream RetryRule `json:"stream"`
	// Breaker: rotation circuit breaker. Attempts = how many consecutive transient failures trip it (default 3, -1 = transient failures do not trip it,
	// a hard failure such as insufficient balance/invalid key still trips immediately); IntervalMS = the fixed cool-down (0 = the default 1/5/30min gradient).
	Breaker RetryRule `json:"breaker"`
	// Intent: rerunning the whole intent after a worker ends with model_error. Default 2 attempts, fixed 3s.
	Intent RetryRule `json:"intent"`
}

// Clamped returns the policy with every rule clamped.
func (p LLMRetryPolicy) Clamped() LLMRetryPolicy {
	p.Connect, p.Empty, p.Stream = p.Connect.Clamped(), p.Empty.Clamped(), p.Stream.Clamped()
	p.Breaker, p.Intent = p.Breaker.Clamped(), p.Intent.Clamped()
	return p
}

// LLMRetryPolicy reads the global retry policy. A missing or unparseable value
// yields the zero policy — i.e. every layer on its built-in default.
func (d *DB) LLMRetryPolicy() LLMRetryPolicy {
	var p LLMRetryPolicy
	if d == nil {
		return p
	}
	raw, ok, err := d.GetSetting(settingLLMRetryPolicy)
	if err != nil || !ok || raw == "" {
		return p
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return LLMRetryPolicy{}
	}
	return p.Clamped()
}

// SetLLMRetryPolicy persists the global retry policy (values are clamped first).
func (d *DB) SetLLMRetryPolicy(p LLMRetryPolicy) error {
	raw, err := json.Marshal(p.Clamped())
	if err != nil {
		return err
	}
	return d.SetSetting(settingLLMRetryPolicy, string(raw))
}
