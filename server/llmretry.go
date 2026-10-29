package server

import (
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// the server-side parsing of the retry policy, see docs/llm-retry-design.md. Of the five layers:
//   - connect / empty response / same-provider safe window "follow the endpoint", and each LLM profile can override
//     the global default (a blank item on a profile inherits the global, and if the global is unset the built-in default is used);
//   - circuit breaker / intent rerun are process-level, with one global copy only.
//
// the global policy reads one settings row from the DB once, and the call sites are all on low-frequency paths (building a provider, work wrap-up,
// saving a config), not worth another cache layer; the circuit-breaker parameters are the exception — they are read on every failure path, so
// applyRetryPolicy pushes them to the Registry to store.

// retryPolicy reads the global policy; a nil DB yields the zero policy (all
// layers on their built-in defaults).
func (s *Server) retryPolicy() db.LLMRetryPolicy {
	if s.m == nil || s.m.pg == nil {
		return db.LLMRetryPolicy{}
	}
	return s.m.pg.LLMRetryPolicy()
}

// resolveRetry layers one profile's override on top of the global policy and
// converts the result into the form agent.Config carries. Rules combine field by
// field, so a profile that only pins an interval still inherits the global count.
func resolveRetry(o db.RetryOverride, pol db.LLMRetryPolicy) agent.RetryConfig {
	connect := o.Connect.Or(pol.Connect)
	empty := o.Empty.Or(pol.Empty)
	stream := o.Stream.Or(pol.Stream)
	return agent.RetryConfig{
		// the count keeps the original "0=default / negative=off" semantics here: the SDK's MaxRetries /
		// EmptyResponseRetries are isomorphic with it, so it can parse them itself.
		ConnectAttempts: connect.Attempts, ConnectInterval: connect.Interval(),
		EmptyAttempts: empty.Attempts, EmptyInterval: empty.Interval(),
		StreamAttempts: stream.Attempts, StreamInterval: stream.Interval(),
	}
}

// applyProfileRetry fills cfg.Retry for a profile read from the DB.
func (s *Server) applyProfileRetry(cfg *agent.Config, p *db.LLMProfile) {
	if p == nil {
		return
	}
	cfg.Retry = resolveRetry(p.Retry, s.retryPolicy())
}

// the defaults for the circuit breaker (rotation cool-down), consistent with llmpool's built-in ones — this only overrides them when "the user configured a value".
// the defaults for intent rerun are in engine.go's modelErrorRetries / modelErrorRetryBackoff.

// applyRetryPolicy pushes the process-wide layers of the policy into the objects
// that consume them on a hot path: the circuit-breaker registry. Called at
// startup and whenever the policy is saved.
func (s *Server) applyRetryPolicy() {
	pol := s.retryPolicy()
	if s.llmHealth != nil {
		s.llmHealth.SetPolicy(pol.Breaker.Attempts, pol.Breaker.Interval())
	}
}

// modelErrorRetryPolicy resolves the intent-level replay knobs (layer ⑤): how
// many times a model_error work is re-run and how long to back off between runs.
func (e *Engine) modelErrorRetryPolicy() (retries int, backoff time.Duration) {
	retries, backoff = modelErrorRetries, modelErrorRetryBackoff
	if e == nil || e.m == nil || e.m.pg == nil {
		return retries, backoff
	}
	rule := e.m.pg.LLMRetryPolicy().Intent
	if rule.Attempts != 0 {
		retries = max(rule.Attempts, 0)
	}
	if d := rule.Interval(); d > 0 {
		backoff = d
	}
	return retries, backoff
}

// emptyTurnNudgeLimit resolves how many empty-turn continuations one work may
// inject (see steerHooks.Stop). It deliberately reuses layer ②'s knob — the "empty-response
// retry count": the two are two means to the same end. The SDK layer handles "no content block at all", by resending
// the same request as-is; this handles "thinking only, no body and no tool", by appending an instruction so the
// model carries on with the thinking it has (resending as-is is pointless for an idle turn determined by the shape of the context). The emptiness definition
// differs because the SDK goes by "whether any event was yielded", and a thinking delta is itself an event — but when a user configures
// "how many empty-response retries" they mean "retry once if the model produced no real content", and the two layers sharing one count
// matches that mental model.
//
// read the global policy rather than a profile's override: a run may switch profile mid-way on failover, while this
// is the total gate for the whole intent and should not change with the endpoint. The semantics are isomorphic with the SDK's emptyRetries():
// 0 = the default defaultEmptyTurnNudges; -1 (negative) = turn off idle continuation; >0 = use this value.
func (e *Engine) emptyTurnNudgeLimit() int {
	if e == nil || e.m == nil || e.m.pg == nil {
		return defaultEmptyTurnNudges
	}
	switch n := e.m.pg.LLMRetryPolicy().Empty.Attempts; {
	case n == 0:
		return defaultEmptyTurnNudges
	case n < 0:
		return 0
	default:
		return n
	}
}
