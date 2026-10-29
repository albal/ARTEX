package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "the user paused the task",
		"The user paused the task through the task control endpoint (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was actively cancelled; a running intent returns to the frontier (open), and after the task resumes it is claimed again and executed from the start")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "an orchestration agent paused the task",
		"An orchestration agent called the pause_task tool to pause this task. This Planner/Worker run was actively cancelled; a running intent returns to the frontier (open) and is executed again after resuming")
	AbortTaskDeleted = cause("task_deleted", "the task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}); the delete barrier has cancelled the task's running Planner, Worker and main agent; the results of this run will no longer be used")
	AbortPausedOnReload = cause("paused_on_reload", "backend restored the paused state",
		"On start-up the backend restored the task's paused state from the state persisted in the database. This run was cancelled; normally no agent is running during the restore phase")
	AbortGoalMet = cause("goal_met", "the planner judged the task goal met",
		"The planner judged the task goal met and set the task to done, then cancelled the Workers still running; those intents are marked stopped rather than failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "task timeout wrap-up wait ran out",
		"After the task reached timeout it waited for the running Workers to wrap up gracefully, but the 90-second drain grace period was still not enough, so a hard cancel was performed; the intents are marked exhausted, and facts and assets already written during wrap-up are kept")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "the planner terminated this intent",
		"The planner called kill_work to actively terminate this intent, usually meaning the direction has gone off track or is no longer worthwhile; the intent is marked stopped and is not re-claimed automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "the user paused this Worker intent",
		"The user paused a running Worker. This call was cancelled and the intent becomes paused; the intents, facts, vulnerabilities and activity records already registered are all kept, and after resuming it is executed again from the start")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "the user deleted this Worker intent",
		"The user deleted a running Worker. This call was cancelled; after the Worker leaves the write section, the server handles the intent according to the delete mode the user chose: a soft delete only marks it deleted and keeps all its output, while a hard delete cascades to remove the intent and the downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished and released context",
		"The Worker finished normally, and the engine released its context resources in detachWork. This is not a run interruption; if it appears in an interruption message, a cancel and a wrap-up event raced")
	AbortPausedRaceGuard = cause("paused_race_guard", "new run refused while task paused",
		"While the task is paused the engine refuses to issue a new execution context, to prevent a race between a claim and the pause from letting a Worker keep starting; a claimed intent returns to the frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "the user stopped this conversation turn",
		"The user clicked stop, actively aborting this main agent or session agent run. Activity records already produced are kept, and the next message can still be sent")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "task pause aborted the conversation",
		"When the user paused the task, the running main agent conversation was cancelled along with it. Activity records already produced are kept; after the task resumes this turn's message is not replayed automatically")
	AbortChatTurnFinished = cause("chat_turn_finished", "conversation turn finished normally",
		"This conversation turn finished normally, and the server is releasing the turn's context resources. This is not a run interruption; if it appears in an interruption message, a cancel and a wrap-up event raced")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "the backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating or shutting down. All running agents are cancelled; after a restart any leftover running intents are reset to open and executed again")
	AbortRunHardTimeout = cause("run_hard_timeout", "single-run hard timeout fired",
		"A single run exceeded the soft wall-clock budget plus the extra grace period, meaning a model request or some tool did not return for a long time, so the normal turn-boundary wrap-up could not run. Focus on the last tool call before the interruption that did not return")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "the upstream context reached its deadline",
			"The upstream context reached its deadline, but the setter did not attach a named cause via WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "the canceller attached no named cause",
			"The upstream context was cancelled, but the canceller did not attach a named cause via context.WithCancelCause; register the cause in agent/cancelcause.go and wire it into that cancel point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
