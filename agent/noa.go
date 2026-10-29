package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is the "model-driven context compaction" mechanism introduced in norma v0.4.0, exposed as a platform experimental feature that the user toggles in
// system settings. It is mutually exclusive with the built-in compaction: noaadapter.Enable is the only entry point and, in one call, attaches
// the context takeover (Compactor), the Compress tool and three resident prompt sections; not calling Enable means it is off
// (built-in compaction works as usual). The toggle is resolved by a noaEnabledFn injected per agent and read once per run,
// so switching it only affects runs started afterwards, with no need to rebuild the agent.

// enableNoa wires noa into opts when the resolver reports it is on. archiveRoot is the base directory where compressed originals are persisted
// (the global workDir; every agent lands under <workDir>/noa rather than being scattered across task/intent directories), and sessionID
// names the archive sub-directory under it (globally unique, so there is no clash within the one base directory).
//
// noa is experimental: a wiring failure must not interrupt a real task. On error it is reported via onWarn and falls back to built-in compaction.
// On success opts.Compaction is cleared, to avoid agentcore warning that "two context managers are set at once".
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("failed to enable noa compaction, falling back to built-in compaction: " + err.Error())
		}
		return
	}
	// Compactor overrides Compaction, but agentcore warns every time when both are set; clear it explicitly.
	opts.Compaction = nil
}
