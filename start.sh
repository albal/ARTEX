#!/bin/sh
# ARTEX supervisor launch script (Linux / macOS / Docker ENTRYPOINT)
#
# Usage:
#   ./start.sh                       run in the foreground (Ctrl-C to stop)
#   nohup ./start.sh >artex.log 2>&1 &   run in the background
#   ./start.sh -addr :9000           extra arguments are passed through to artex unchanged
#
# It does one thing: run artex, and after the process exits decide from the exit code whether to relaunch it.
#
#   0      the user stopped normally   → leave the loop
#   75     the program requested a restart → rerun immediately (the web UI clicked "one-click update" or "rollback")
#   other  crash                       → rerun after backoff (1→2→4… up to 60 seconds)
#
# It deliberately does no download, SHA256 verification or swap here: that logic would have to be written twice for sh and bat,
# and it is exactly the part that must not go wrong — once a binary that cannot run is swapped in, this script would faithfully
# relaunch it over and over, leaving the user to rescue it by hand on the machine. So verification/swap all stay in Go (the selfupdate package),
# done by artex itself at start-up, and the script stays simple.
set -u

cd "$(dirname "$0")" || exit 1

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] cannot find the executable $BIN" >&2; exit 1; }

RESTART_CODE=75
MAX_DELAY=60

child=0
stopping=0

# forward the stop signal to the artex binary.
#
# under Docker this is required: docker stop only sends SIGTERM to PID 1 (i.e. this script),
# not to the child process. Without forwarding, artex would not receive the signal, could not shut down gracefully, and would be hard-killed
# by SIGKILL after 10 seconds, cutting running tasks off half-way.
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# a signal interrupts wait and makes it return >128. At that point the child is still shutting down gracefully,
	# so wait once more to get its real exit code.
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[artex] stopped"
		exit 0
	fi

	case "$code" in
		0)
			echo "[artex] exited normally"
			exit 0
			;;
		"$RESTART_CODE")
			# an update/rollback is ready: after rerunning, artex completes the swap at start-up (see selfupdate.Bootstrap).
			echo "[artex] restart requested (applying the new version)…"
			delay=1
			;;
		*)
			echo "[artex] abnormal exit (code=$code), restarting in ${delay}s" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
