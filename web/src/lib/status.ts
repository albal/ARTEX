// Centralised status → color/label semantics, reused across the whole app.
// Spec §8.3: intent / coverage / task / severity each have a consistent colour set.

export type Tone = "neutral" | "blue" | "green" | "amber" | "red" | "rose" | "violet" | "slate";

export const toneClasses: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-transparent",
  blue: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/20",
  green: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
  amber: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/20",
  red: "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/20",
  // rose is used for "critical": solid and high-emphasis, visibly above the soft red outline of "high".
  rose: "bg-rose-600 text-white border-rose-600 dark:bg-rose-600 dark:text-white",
  violet: "bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/20",
  slate: "bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/20",
};

export const toneDot: Record<Tone, string> = {
  neutral: "bg-muted-foreground",
  blue: "bg-blue-500",
  green: "bg-emerald-500",
  amber: "bg-amber-500",
  red: "bg-red-500",
  rose: "bg-white",
  violet: "bg-violet-500",
  slate: "bg-slate-500",
};

interface StatusMeta {
  label: string;
  tone: Tone;
}

const intent: Record<string, StatusMeta> = {
  open: { label: "Pending claim", tone: "slate" },
  running: { label: "In progress", tone: "blue" },
  paused: { label: "Paused", tone: "amber" },
  done: { label: "Completed", tone: "green" },
  // blocked = model/API/network fault retries exhausted; this intent was barely explored at all (not a goal block).
  blocked: { label: "Execution error", tone: "red" },
  // exhausted = cut off part-way by hitting the turn/time budget, with only partial results written back (not a direction fully explored).
  exhausted: { label: "Budget exhausted", tone: "violet" },
  // stopped = historical soft-delete state (kept for historical data).
  stopped: { label: "Stopped", tone: "slate" },
  // deleted = the user soft-deleted this intent (node and lineage kept; the deletion reason is in the delete_reason field).
  deleted: { label: "Deleted", tone: "slate" },
};

const task: Record<string, StatusMeta> = {
  created: { label: "Created", tone: "slate" },
  queued: { label: "Queued", tone: "amber" },
  running: { label: "In progress", tone: "blue" },
  paused: { label: "Paused", tone: "amber" },
  done: { label: "Completed", tone: "green" },
  failed: { label: "Failed", tone: "red" },
  timeout: { label: "Timed out", tone: "amber" },
};

const severity: Record<string, StatusMeta> = {
  critical: { label: "Severe", tone: "rose" },
  high: { label: "High Risk", tone: "red" },
  medium: { label: "Medium Risk", tone: "amber" },
  low: { label: "Low Risk", tone: "slate" },
};

const finding: Record<string, StatusMeta> = {
  pending: { label: "Pending", tone: "amber" },
  in_progress: { label: "Processing", tone: "blue" },
  confirmed: { label: "Confirmed", tone: "red" },
  resolved: { label: "Processed", tone: "green" },
  fixed: { label: "Resolved", tone: "green" },
  false_positive: { label: "False positive", tone: "slate" },
  ignored: { label: "Ignore", tone: "neutral" },
  duplicate: { label: "Duplicate", tone: "neutral" },
  risk_accepted: { label: "Risk accepted", tone: "violet" },
};

const engine: Record<string, StatusMeta> = {
  exploring: { label: "Exploring", tone: "blue" },
  paused: { label: "Paused", tone: "amber" },
  stalled: { label: "Stalled", tone: "red" },
  idle: { label: "Idle", tone: "neutral" },
};

const goal: Record<string, StatusMeta> = {
  open: { label: "In progress", tone: "blue" },
  met: { label: "Achieved", tone: "green" },
  abandoned: { label: "Abandoned", tone: "slate" },
};

const audit: Record<string, StatusMeta> = {
  allow: { label: "Allow", tone: "green" },
  block: { label: "Block", tone: "red" },
};

const node: Record<string, StatusMeta> = {
  observed: { label: "Observe", tone: "slate" },
  confirmed: { label: "Confirm", tone: "green" },
  tombstoned: { label: "Deprecated", tone: "neutral" },
};

// Notification delivery status. sending uses blue rather than amber: it is not "something is wrong"
// but "claimed and being sent", which must be distinguishable from pending's waiting meaning.
const delivery: Record<string, StatusMeta> = {
  pending: { label: "Pending", tone: "amber" },
  sending: { label: "Sending", tone: "blue" },
  sent: { label: "Delivered", tone: "green" },
  failed: { label: "Failed", tone: "red" },
  skipped: { label: "Skipped", tone: "neutral" },
};

const maps = {
  intent,
  task,
  severity,
  finding,
  engine,
  goal,
  audit,
  node,
  delivery,
} as const;

export type StatusDomain = keyof typeof maps;

export function statusMeta(domain: StatusDomain, key: string): StatusMeta {
  return maps[domain][key] ?? { label: key, tone: "neutral" };
}
