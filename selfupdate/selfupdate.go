// Package selfupdate implements ARTEX's one-click update from the web UI: it fetches the new binary from a GitHub Release,
// verifies it, stages it, and swaps it in atomically at the next start-up.
//
// Division of labour (see start.sh / start.bat):
//
//	start-up script = a simple supervisor loop, only responsible for "deciding from the exit code whether to relaunch after the process exits"
//	this package    = all the error-prone logic (download / SHA256 verification / smoke test / swap / rollback on failure)
//
// The swap lives in Go rather than in the scripts because SHA256 verification and smoke testing would have to be written twice for sh and bat
// (sha256sum / shasum / certutil), and that is exactly the step that must not go wrong: swap in a binary
// that cannot run and the supervisor will faithfully relaunch it over and over, leaving the user to rescue it by hand on the machine.
//
// A complete upgrade goes through three process start-ups:
//
//	① the old server receives /api/update/apply → download and verify → stage artex.new → exit 75
//	② the script relaunches the old version → Bootstrap finds artex.new → verify + smoke test → swap → exit 75
//	③ the script relaunches, now the new version → Bootstrap records an attempt → clears the marker once start-up succeeds
//
// Any failed step falls back to the old version: if ② fails verification the staged file is deleted and the old version keeps running; if ③ fails 3 times in a row to survive
// until the marker is cleared (crashing because it cannot start), artex.old is swapped back automatically.
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExitRestart is the "please, supervisor, relaunch me" exit code (EX_TEMPFAIL). When the start-up script sees it
// it reruns immediately without counting it towards crash backoff. 0 means the user stopped normally (the script leaves the loop); everything else is treated as a crash.
const ExitRestart = 75

// maxAttempts is the number of start-up attempts allowed after a swap. Each start of the new version adds 1 to the count, and surviving
// settleDelay clears the marker; crashing maxAttempts times in a row means the new version cannot start at all, so it rolls back automatically.
const maxAttempts = 3

// Paths holds every file involved in an upgrade, all placed in **the directory containing the executable**.
// The CWD is deliberately not used: when running as a service the working directory may be / or any path, and using the CWD would put the staged file
// somewhere else, breaking the swap logic outright.
type Paths struct {
	Dir     string // directory containing the executable
	Current string // currently running binary        artex      / artex.exe
	New     string // staged new version              artex.new  / artex.new.exe
	Sum     string // sha256 of the new version (hex) artex.new.sha256 / artex.new.exe.sha256
	Old     string // old version backed up before the swap  artex.old  / artex.old.exe
	Marker  string // upgrade state marker            artex.upgrade.json
}

// ResolvePaths derives every upgrade path from the current executable.
//
// On Windows .new/.old must also carry the .exe suffix, otherwise the smoke test and execution after the swap would fail,
// so the suffix is stripped first and then re-added, keeping the naming symmetrical on both platforms.
func ResolvePaths() (Paths, error) {
	exe, err := os.Executable()
	if err != nil {
		return Paths{}, fmt.Errorf("locate executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	name := filepath.Base(exe)
	ext := filepath.Ext(name) // ".exe" on Windows, usually empty on Unix
	stem := strings.TrimSuffix(name, ext)

	join := func(suffix string) string { return filepath.Join(dir, stem+suffix+ext) }
	return Paths{
		Dir:     dir,
		Current: exe,
		New:     join(".new"),
		Sum:     join(".new") + ".sha256",
		Old:     join(".old"),
		Marker:  filepath.Join(dir, stem+".upgrade.json"),
	}, nil
}

// marker records the progress of a swap, used to trigger an automatic rollback if the new version cannot start.
type marker struct {
	From     string `json:"from"`     // version before the upgrade
	To       string `json:"to"`       // target version
	Attempts int    `json:"attempts"` // start-up attempts since the swap
	StagedAt int64  `json:"staged_at"`
}

func readMarker(path string) (marker, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return marker{}, false
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{}, false
	}
	return m, true
}

func writeMarker(path string, m marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cleanStaged removes the staged files. A successful swap, failed verification and user cancellation all go through it, so a leftover
// artex.new is not retried at the next start-up.
func cleanStaged(p Paths) {
	_ = os.Remove(p.New)
	_ = os.Remove(p.Sum)
}

// CompareVersions compares two version numbers, returning -1/0/1 (a<b / a==b / a>b).
// ok=false means at least one side is not a comparable version number (for example a local development build's "dev" or
// the "0.3.7-2-gabc1234-dirty" produced by git describe); the caller should then disable one-click update,
// otherwise a build under development would be "upgraded" to a release, overwriting uncommitted changes.
func CompareVersions(a, b string) (int, bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := range 3 {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion parses a version number of the form "v0.3.7" / "0.3.7" into [3]int.
//
// Only the clean three-part form is accepted: for non-tag builds build.sh uses git describe to produce
// suffixed versions like "0.3.7-2-gabc1234", which must be judged not comparable rather than treated as
// 0.3.7; otherwise development builds would be misjudged as "already up to date" or overwritten by a release.
func parseVersion(s string) ([3]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// InDocker reports whether the process is running in a container. Under Docker the swap writes to the container's writable layer,
// and `docker compose up -d` recreating the container reverts to the version in the image; this is expected behaviour
// (the user would be pulling a new image at that point anyway), but the frontend needs to know so it can explain it clearly.
func InDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "containerd")
}
