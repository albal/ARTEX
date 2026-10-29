@echo off
rem switch the console to UTF-8 so output is not garbled in a legacy code page.
chcp 65001 >nul 2>&1
rem ARTEX supervisor launch script (Windows)
rem
rem Usage:
rem   start.bat                  run in the foreground (Ctrl-C to stop)
rem   start.bat -addr :9000      extra arguments are passed through to artex unchanged
rem
rem It does one thing: run artex.exe, and after the process exits decide from the exit code whether to relaunch it.
rem
rem   0      the user stopped normally  -> leave the loop
rem   75     the program requested a restart  -> rerun immediately (the web UI clicked "one-click update" or "rollback")
rem   other  crash              -> rerun after backoff (1->2->4… up to 60 seconds)
rem
rem download, SHA256 verification and swap are not here; they are all done by artex itself at start-up
rem (the selfupdate package). The script stays simple; see the notes at the top of start.sh for details.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=artex.exe"
if not exist "%BIN%" (
	echo [artex] cannot find the executable %BIN% 1>&2
	exit /b 1
)

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [artex] exited normally
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	rem an update/rollback is ready: after rerunning, artex completes the swap at start-up.
	echo [artex] restart requested (applying the new version)…
	set /a delay=1
	goto loop
)

echo [artex] abnormal exit ^(code=!code!^), restarting in !delay!s 1>&2
rem timeout fails in a redirected console, so ping is used as a fallback (an N-second delay needs N+1 pings).
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
