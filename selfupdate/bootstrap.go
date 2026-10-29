package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// smokeEnv makes child processes launched by the smoke test skip Bootstrap entirely.
//
// Strictly speaking nothing would go wrong without it: the child's os.Executable() is artex.new, so every path it derives
// carries the .new prefix and cannot touch the real upgrade files. But relying on that coincidence is too fragile;
// an explicit short circuit is obvious at a glance and also saves the child a pointless disk probe.
const smokeEnv = "ARTEX_SELFUPDATE_SMOKE"

// Action is Bootstrap's instruction to main.
type Action int

const (
	// Continue: start the server as usual.
	Continue Action = iota
	// Restart: exit immediately with ExitRestart so the supervisor script relaunches us.
	Restart
)

// State describes the upgrade state at this start-up, so /api/update/check can tell the frontend truthfully
// "whether the last upgrade succeeded or was rolled back".
type State struct {
	Pending     bool   // swapped in but not yet confirmed stable
	RolledBack  bool   // an automatic rollback has just been performed at this start-up
	FailedStage bool   // the staged file failed verification/smoke testing and was discarded
	Detail      string // one-sentence explanation for the user
}

// Bootstrap runs at the very start of main and must be called before listening on any port or opening the database.
//
// Three situations:
//
//	① a staged artex.new exists  → verify + smoke test; if it passes, swap it in and request a restart; otherwise discard it and keep running the old version
//	② only the marker file remains → we have just swapped; count one attempt, and roll back after enough consecutive failures
//	③ nothing at all             → normal start-up
func Bootstrap() (Action, State) {
	if os.Getenv(smokeEnv) != "" {
		return Continue, State{}
	}
	p, err := ResolvePaths()
	if err != nil {
		log.Printf("[update] skipping bootstrap: %v", err)
		return Continue, State{}
	}

	if _, err := os.Stat(p.New); err == nil {
		return applyStaged(p)
	}

	m, ok := readMarker(p.Marker)
	if !ok {
		return Continue, State{}
	}
	return confirmOrRollback(p, m)
}

// applyStaged handles the "staged file exists" situation: swap it in if verification passes, discard it if it fails.
//
// This is the only place in the whole upgrade chain that overwrites the executable, and the last gate: the smoke test stops
// corrupt downloads, the wrong architecture and missing dynamic libraries. Once a binary that cannot run gets through,
// the supervisor script will tirelessly relaunch it over and over, the Go code never gets a chance to run, and automatic rollback is out of the question.
func applyStaged(p Paths) (Action, State) {
	m, _ := readMarker(p.Marker)

	if err := verifyStaged(p); err != nil {
		log.Printf("[update] the staged new version failed verification and was discarded; continuing with the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "New version failed verification and was discarded: " + err.Error()}
	}

	if err := swap(p); err != nil {
		log.Printf("[update] swap failed; continuing with the current version: %v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "Swap failed: " + err.Error()}
	}

	// Swap succeeded. Keep the marker for the next start-up (which runs the new version) to confirm it is stable.
	m.Attempts = 0
	if m.StagedAt == 0 {
		m.StagedAt = time.Now().Unix()
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to write the upgrade marker (automatic rollback unavailable): %v", err)
	}
	log.Printf("[update] swapped to %s; exiting to restart (exit %d)", orUnknown(m.To), ExitRestart)
	return Restart, State{Pending: true}
}

// confirmOrRollback handles "the start-up after a swap": count the attempts and swap the old version back once the limit is exceeded.
//
// The count only increments once the Go code is running, so it covers failures of the "executes but crashes during initialisation"
// kind (incompatible configuration, port in use, DB migration blew up); "cannot exec at all" is stopped by the
// smoke test before the swap, and only the two together are complete.
func confirmOrRollback(p Paths, m marker) (Action, State) {
	m.Attempts++
	if m.Attempts > maxAttempts {
		if err := rollback(p); err != nil {
			// If even the rollback failed, stop restarting, otherwise we would be stuck in an endless restart loop. Clear the marker
			// and let the process start in its current state; if it cannot, at least the user can see why in the logs.
			log.Printf("[update] the new version failed to start %d times in a row, and the rollback failed: %v", maxAttempts, err)
			_ = os.Remove(p.Marker)
			return Continue, State{Detail: "New version failed to start and the rollback failed: " + err.Error()}
		}
		log.Printf("[update] the new version failed to start %d times in a row; rolled back to %s, exiting to restart (exit %d)",
			maxAttempts, orUnknown(m.From), ExitRestart)
		_ = os.Remove(p.Marker)
		return Restart, State{RolledBack: true, Detail: fmt.Sprintf("New version failed to start; rolled back to %s", orUnknown(m.From))}
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] failed to update the upgrade marker: %v", err)
	}
	log.Printf("[update] new version starting (attempt %d/%d); the upgrade will be confirmed once it runs stably",
		m.Attempts, maxAttempts)
	return Continue, State{Pending: true}
}

// Settle confirms the new version is running stably and clears the upgrade marker.
//
// Called by main after a delay once HTTP is listening: it only counts if it survives that long; otherwise the marker stays in place
// and the next start-up keeps counting attempts until a rollback is triggered.
func Settle() {
	p, err := ResolvePaths()
	if err != nil {
		return
	}
	settle(p)
}

func settle(p Paths) {
	if _, ok := readMarker(p.Marker); !ok {
		return // not a start-up after an upgrade; nothing to do
	}
	if err := os.Remove(p.Marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[update] failed to clear the upgrade marker: %v", err)
		return
	}
	log.Printf("[update] new version running stably; upgrade complete (previous version kept as %s)", p.Old)
}

// SettleDelay is how long it must run before "the new version has survived".
const SettleDelay = 30 * time.Second

// verifyStaged verifies the staged file: first compare the SHA256, then actually launch it once.
func verifyStaged(p Paths) error {
	want, err := os.ReadFile(p.Sum)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}
	got, err := fileSHA256(p.New)
	if err != nil {
		return fmt.Errorf("compute checksum: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(want)), got) {
		return errors.New("SHA256 mismatch (download corrupted or tampered with)")
	}
	return smokeTest(p.New)
}

// smokeTest launches the new binary with -h to confirm it really executes on the current system.
// This stops a whole class of problems: truncated downloads, the wrong architecture (exec format error), missing dependencies and so on.
func smokeTest(bin string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("set execute permission: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-h")
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return errors.New("smoke test timed out (new binary not responding)")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("smoke test failed: %v: %s", err, snippet)
	}
	return nil
}

// swap replaces the current binary with the staged new version.
//
// Both Unix and Windows allow renaming a running executable (Windows forbids deleting and
// overwriting it, but not renaming), so there is no need for per-platform code here, nor to stop ourselves first.
func swap(p Paths) error {
	// On Windows rename does not overwrite an existing target, so the .old left by the previous upgrade must be cleared first.
	if err := os.Remove(p.Old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clean up old backup %s: %w", p.Old, err)
	}
	if err := os.Rename(p.Current, p.Old); err != nil {
		return fmt.Errorf("back up current version: %w", err)
	}
	if err := os.Rename(p.New, p.Current); err != nil {
		// The swap failed but the current version has already been moved away; it must be put back as it was, otherwise the next start-up has no executable.
		if rerr := os.Rename(p.Old, p.Current); rerr != nil {
			return fmt.Errorf("installing the new version failed (%v), and restoring the current version failed: %w", err, rerr)
		}
		return fmt.Errorf("install new version: %w", err)
	}
	_ = os.Remove(p.Sum)
	return nil
}

// rollback swaps back the old version backed up by swap.
func rollback(p Paths) error {
	if _, err := os.Stat(p.Old); err != nil {
		return fmt.Errorf("no backup %s to roll back to: %w", p.Old, err)
	}
	// Move the new version that could not start to .failed for diagnosis rather than deleting it.
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(p.Current, failed); err != nil {
		return fmt.Errorf("move away failed version: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		return fmt.Errorf("restore old version: %w", err)
	}
	return nil
}

// Rollback implements /api/update/rollback: actively go back to the previous version.
// It only does the swap; restarting is likewise left to the supervisor script (the caller then exits with ExitRestart).
func Rollback() error {
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Old); err != nil {
		return errors.New("no previous version to roll back to (" + p.Old + " does not exist)")
	}
	cleanStaged(p)
	if err := smokeTest(p.Old); err != nil {
		return fmt.Errorf("the previous version cannot execute; refusing to roll back: %w", err)
	}
	// Swap the current and backup versions: after a rollback you can still roll forward again.
	tmp := p.Current + ".swap"
	_ = os.Remove(tmp)
	if err := os.Rename(p.Current, tmp); err != nil {
		return fmt.Errorf("move away current version: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		_ = os.Rename(tmp, p.Current)
		return fmt.Errorf("install previous version: %w", err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		log.Printf("[update] failed to tidy up the backup after rollback (does not affect running): %v", err)
	}
	_ = os.Remove(p.Marker)
	return nil
}

// HasBackup reports whether a previous version is available to roll back to, so the frontend can decide whether to show the rollback button.
func HasBackup() bool {
	p, err := ResolvePaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(p.Old)
	return err == nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown version"
	}
	return s
}
