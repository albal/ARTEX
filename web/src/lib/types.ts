// ARTEX domain model — types used across the UI.
// Derived from the functional spec (section 7: key data shapes).

export type TaskStatus = "created" | "queued" | "running" | "paused" | "done" | "failed" | "timeout";
export type EngineMode = "exploring" | "paused" | "stalled" | "idle";

export interface Task {
  id: string;
  name?: string; // optional task name; empty/absent = unnamed, display falls back to the description
  category_id?: number;
  category_name?: string;
  pinned?: boolean;
  pinned_at?: string | null;
  description: string;
  goal: string;
  status: TaskStatus;
  created_at: string;
  created_unix?: number; // created_at as unix seconds (run-duration calc)
  completed_at?: string; // RFC3339 finish time (done/failed); "" if unfinished
  completed_unix?: number; // completed_at as unix seconds (0/undef if unfinished)
  last_activity_unix?: number; // unix seconds of the last activity (0/undef if none)
  paused?: boolean;
  queued?: boolean;
  active?: boolean;
  in_flight?: number;
  findings?: { critical: number; high: number; medium: number; low: number }; // recorded vulnerability counts (by severity)
  last_activity?: string;
  stalled?: boolean;
  goals_total?: number;
  goals_met?: number;
  engine_mode?: EngineMode;
  tokens?: TokenTotal; // whole-task token consumption
  llm_profile_id?: number; // LLM profile used; absent = default profile
  llm_profile_ids?: number[]; // ordered task-level failover chain
  active_llm_profile_id?: number; // profile used by the next LLM call
  llm_failover_state?: "default" | "ready" | "chain_exhausted" | string;
  llm_failover_reason?: string;
  source_task_ids?: string[]; // directly related tasks inherited as read-only context
  archive_blocked_by_task_id?: string; // live direct dependent that must be archived first
  company_ids?: number[]; // associated company scopes; current company assets join the task at creation
  coverage_enabled?: boolean; // asset coverage feature toggle (fixed at creation, on by default); false = not computed/not shown
}

export interface TaskCategory {
  id: number;
  name: string;
  task_count: number;
  created_at: string;
  updated_at: string;
}

export interface TaskTemplate {
  id: number;
  name: string;
  description: string;
  goal: string;
  category_id?: number | null; // preset category; null/absent = none
  intercept_rules?: AssetInterceptRuleInput[]; // preset task-level block/allow rules
  created_at: string;
  updated_at: string;
}

export interface DeleteTaskOptions {
  delete_assets: boolean;
  delete_traffic: boolean;
  delete_files: boolean;
  delete_findings: boolean;
  delete_llm_records: boolean;
}

export interface DeleteTaskResult {
  deleted: string;
  assets_deleted: number;
  assets_detached: number;
  traffic_deleted: number;
  files_deleted: boolean;
  findings_deleted: number;
  llm_records_deleted: number;
  cleanup_warning?: string;
}

export type TaskArchiveState =
  | "archive_queued"
  | "archiving"
  | "archive_failed"
  | "ready"
  | "restore_queued"
  | "restoring"
  | "restore_failed"
  | "delete_queued"
  | "deleting"
  | "delete_failed";

export interface TaskArchiveTokenStats {
  calls?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface TaskArchive {
  id: number;
  task_id: number;
  state: TaskArchiveState;
  phase: string;
  progress: number;
  error?: string;
  warnings?: string[];
  format_version: number;
  sha256?: string;
  original_size: number;
  compressed_size: number;
  task_name: string;
  task_description: string;
  task_goal: string;
  original_status: TaskStatus;
  category_id?: number;
  category_name?: string;
  source_task_ids: number[];
  remaining_timeout_seconds: number;
  data_counts: Record<string, number>;
  aggregate_stats: {
    tokens?: TaskArchiveTokenStats;
    skills?: Record<string, number>;
    tools?: Record<string, number>;
    findings?: Record<string, number>;
  };
  archived_at?: string;
  requested_at: string;
  created_at: string;
  updated_at: string;
}

export interface TaskArchivePage {
  items: TaskArchive[];
  total: number;
  page: number;
  size: number;
}

export interface ArchiveBatchItem {
  id: string;
  archive_id?: number;
  ok: boolean;
  queued: boolean;
  error?: string;
}

// ---- Asset graph (global, shared across tasks) ----
export type AssetType =
  | "company"
  | "domain"
  | "ip"
  | "port"
  | "service"
  | "site"
  | "endpoint"
  | "parameter"
  | "tech"
  | "credential"
  | "data";

export type NodeState = "observed" | "confirmed" | "tombstoned";

export interface AssetNode {
  id: string;
  type: AssetType;
  name: string;
  key: string; // nkey
  value?: string;
  company_id?: string; // owning company asset id; empty = unassigned
  state: NodeState;
  confidence: number; // 0..1
  attrs?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export type AssetRel =
  | "owns"
  | "resolves"
  | "exposes"
  | "runs"
  | "serves"
  | "has_endpoint"
  | "has_param"
  | "fingerprinted"
  | "authenticates_as"
  | "reachable"
  | "has_subdomain";

export interface Edge {
  src: string;
  dst: string;
  rel: AssetRel | ExploreRel;
}

// Task asset view — server-side enriched, paginated.
export interface TaskAssetRef {
  id: string;
  name?: string;
  key: string;
  attrs?: Record<string, unknown>;
}

export interface TaskAssetItem extends AssetNode {
  techs?: TaskAssetRef[];
  auth?: TaskAssetRef[];
  params?: TaskAssetRef[];
}

export interface TaskAssetView {
  counts: Record<string, number>;
  total: number;
  items: TaskAssetItem[];
}

// ---- New unified asset model (new backend) ----
export type NewAssetType = "root_domain" | "ip" | "subdomain" | "app" | "service" | "endpoint";

export interface Asset {
  id: number;
  type: NewAssetType;
  company_id?: number;
  task_ids: number[];
  domain?: string;
  root_domain?: string;
  ip?: string;
  c_segment?: string;
  port?: number;
  icp?: string;
  bound_domains?: string[];
  open_ports?: { port: number; service?: string }[];
  record_type?: string;
  record_value?: string[] | string;
  bundle_id?: string;
  app_name?: string;
  category?: string;
  app_description?: string;
  app_icp?: string;
  url?: string;
  service_type?: string;
  service_name?: string;
  favicon_mmh3?: string;
  status_code?: number;
  content_length?: number;
  page_title?: string;
  technologies?: string[];
  auth?: Record<string, unknown>[];
  method?: string;
  params?: Record<string, unknown>[];
  extra?: Record<string, unknown>;
  last_seen: string;
  task_source?: string;
  task_source_summary?: string;
  task_source_node_id?: number;
}

export interface IntentAsset {
  intent_id: number | string;
  asset_id: number;
  type: NewAssetType;
  label: string;
  source: string;
  source_summary: string;
  source_node_id?: number;
  source_task_id: number;
  inherited: boolean;
}

export interface TaskAssetMutation {
  requested: number;
  attached: number;
  existing: number;
}

export interface TaskAssetScopeMutation {
  requested: number;
  assets_linked: number;
  assets_existing: number;
  scopes_added: number;
  scopes_existing: number;
}

// ---- Asset coverage graph (per task) ----
// A node in the force-directed "asset coverage graph". key is unique: asset = "a:<id>", company = "c:<id>",
// root domain with no asset row = "r:<domain>". Nodes with in_scope=false are grey context nodes used only for links.
export interface CoverageGraphNode {
  key: string;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";
  label: string;
  tested: boolean;
  in_scope: boolean;
  asset_id?: number;
  company_id?: number;
  domain?: string;
  root_domain?: string;
  ip?: string;
  url?: string;
  port?: number;
  service_type?: string;
  app_name?: string;
  page_title?: string;
  status_code?: number;
}

export interface CoverageGraphEdge {
  src: string;
  dst: string;
}

export interface CoverageGraphData {
  nodes: CoverageGraphNode[];
  edges: CoverageGraphEdge[];
}

// Intents/facts/findings linked to an asset in this task's exploration graph (for the coverage graph node drawer).
export interface CoverageAssetRef {
  id: number;
  kind: string;
  state: string;
  summary: string;
  source_task_id?: string;
  inherited?: boolean;
}
export interface CoverageAssetRefs {
  intents: CoverageAssetRef[];
  facts: CoverageAssetRef[];
  findings: CoverageAssetRef[];
}

// ---- Workspace file manager (workDir) ----
export interface WorkspaceEntry {
  name: string;
  path: string; // workspace-relative, forward slashes
  dir: boolean;
  size: number;
  mtime: number; // unix millis
}
export interface WorkspaceListing {
  path: string;
  entries: WorkspaceEntry[];
}
export interface WorkspaceFile {
  path: string;
  size: number;
  binary: boolean;
  too_large?: boolean;
  content?: string;
}

// One entry in a task's test scope (coverage denominator + authorisation boundary).
export interface TaskScopeRow {
  id: number;
  task_id: number;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "cidr" | "icp" | "keyword";
  company_id?: number;
  company_name?: string; // resolved by a backend JOIN on companies; only set when kind=company
  domain?: string;
  net?: string;
  value?: string;
  source: "auto" | "agent" | "manual";
  reason?: string;
}

export type CompanyScopeKind = "domain" | "ip" | "cidr" | "icp" | "keyword";

// Structured asset scope rules submitted when adding a company.
export interface CompanyScopeRule {
  kind: CompanyScopeKind;
  value: string;
}

// Result of writing an asset scope. errors are the invalid lines in this submission; warnings are pre-existing
// data problems unrelated to this submission that would make ownership come out unexpectedly (e.g. assets whose ip field holds a hostname).
export interface CompanyScopeMutation {
  added: number;
  skipped: number;
  invalid: number;
  errors?: string[];
  warnings?: string[];
}

// One company asset scope rule (the single source of truth for ownership).
export interface ScopeRow {
  id: number;
  company_id: number;
  kind: CompanyScopeKind;
  domain?: string; // set when kind=domain
  net?: string; // set when kind=ip|cidr
  value?: string; // may be returned directly by the backend when kind=icp|keyword
  raw: string; // original user input, used for display and refilling the form
  reason?: string;
}

// Company: an asset node with type=company + logo + asset count + asset scope rules.
export interface Company {
  id: number;
  name: string;
  logo?: string; // remote logo URL; if empty the frontend uses the name's initial
  asset_count: number;
  scope?: ScopeRow[];
}

// ---- Exploration graph (per task) ----
export type ExploreKind = "task" | "begin" | "goal" | "intent" | "fact" | "finding" | "hint" | "digest";
export type GoalState = "open" | "met" | "abandoned";
export type IntentState = "open" | "running" | "paused" | "done" | "blocked" | "exhausted" | "stopped";
export type FindingState = "confirmed" | "dismissed";
export type HintState = "active" | "consumed";
export type ExploreRel = "spawns" | "derived_from" | "yields" | "proves" | "covers";

export interface TaskNode {
  id: string;
  type: ExploreKind;
  payload?: string;
  priority: number; // 0..10
  state: string; // GoalState | IntentState | FindingState | HintState
  origin: string;
  ts: string;
  source_task_id?: string;
  inherited?: boolean;
  delete_reason?: string; // deletion reason when an intent is soft-deleted (state='deleted')
}

// A page of the broadcast board: nodes paged in creation order + the edges this page touches + the nodes at the far end of those edges (refs, indexed by id),
// so each broadcast can explain "where it came from and what it produced" without pulling the whole graph.
export interface ExplorationNodePage {
  items: TaskNode[];
  total: number;
  page: number;
  size: number;
  edges: Edge[];
  refs: Record<string, TaskNode>;
  // Node id → the assets that node is anchored to (shown when the broadcast board expands; covers this page's nodes and their neighbours).
  assets: Record<string, FindingAsset[]>;
}

export interface ExplorationNodeQuery {
  page?: number;
  size?: number;
  kinds?: ExploreKind[];
  states?: string[];
  q?: string;
  order?: "asc" | "desc";
}

// Goal used by the goal management card (the backend has already split the payload into text/vulnclass).
export interface TaskGoal {
  id: string;
  text: string;
  vulnclass?: string;
  state: string; // GoalState
  origin?: string;
  ts: string;
}

// Operational constraint used by the constraint management card (allow = permitted / deny = forbidden).
export type ConstraintKind = "allow" | "deny";
export interface TaskConstraint {
  id: string;
  kind: ConstraintKind;
  text: string;
  origin?: string;
  ts?: string;
}

// ---- Findings ----
export type Severity = "critical" | "high" | "medium" | "low";

// Vulnerability triage status: open / in progress / confirmed / handled / fixed / false positive / ignored / duplicate / risk accepted.
export type FindingStatus =
  | "pending"
  | "in_progress"
  | "confirmed"
  | "resolved"
  | "fixed"
  | "false_positive"
  | "ignored"
  | "duplicate"
  | "risk_accepted";

// FindingAsset is an asset bound to a vulnerability (label pre-rendered by the backend).
export interface FindingAsset {
  id: string;
  type: string;
  label: string;
}

export interface Finding {
  traffic_count?: number;
  evidence_version?: number;
  report_evidence_version?: number;
  report_stale?: boolean;
  id: string;
  finding_id?: string; // row id in the standalone findings table, the handle for status updates (may be missing on older in-task nodes)
  vulnclass: string;
  name?: string; // vulnerability name; display falls back to vulnclass when empty
  severity: Severity;
  status: FindingStatus;
  summary: string;
  evidence: string;
  report?: string; // detailed report (Markdown); only returned by the detail endpoint, empty in lists
  intent_id?: string;
  param_id?: string;
  task_id?: string;
  task_description?: string;
  source_task_id?: string;
  inherited?: boolean;
  assets?: FindingAsset[];
  ts: string;
}

// FindingsPage is the server-side paginated response for the findings list.
export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingGroup {
  task_id: string | number | null;
  task_name?: string; // optional task name; empty/absent = unnamed
  task_description: string;
  task_status: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingGroupsPage {
  items: FindingGroup[];
  total: number;
  finding_total: number;
  page: number;
  page_size: number;
}

export interface FindingDeepenResponse {
  task_id: string;
  intent_id: string;
  state: IntentState;
  queued: boolean;
}

// FindingStats is the whole-table aggregate for findings (stat cards + vulnerability type dropdown), computed server-side and unaffected by paging.
export interface FindingStats {
  total: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  vulnclasses: string[];
  tasks: FindingTaskOption[];
}

// FindingTaskOption is one entry in the findings page "by task" filter dropdown: a task that has vulnerabilities (an empty description means the task was deleted;
// the frontend falls back to showing the id) and its vulnerability count.
export interface FindingTaskOption {
  id: string | number;
  name?: string; // optional task name; empty/absent = unnamed
  description: string;
  count: number;
}

// FindingQuery holds the findings list paging/filter/sort parameters.
export interface FindingQuery {
  page: number;
  pageSize: number;
  severity?: "all" | Severity;
  status?: "all" | FindingStatus;
  vulnclass?: string;
  task?: string; // task id; "all"/empty = do not filter by task
  query?: string;
  sort?: "severity" | "time";
  // Asset tree node key; selecting a node selects its whole subtree. Empty = do not filter by asset.
  assetScope?: string;
}

// ---- Findings by asset (asset view) ----
export type FindingAssetKind = "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint" | "none";

// FindingAssetNode is a node in the asset tree. key looks like a:<id> (asset), c:<id> (company),
// r:<domain> (root domain with no asset row in the database), __none__ (no linked asset).
export interface FindingAssetNode {
  key: string;
  parent?: string;
  kind: FindingAssetKind;
  label: string;
  asset_id?: number;
  company_id?: number;
  self: number; // findings attached directly to this asset
  total: number; // including descendants, de-duplicated by finding
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingAssetTree {
  nodes: FindingAssetNode[];
  finding_total: number;
  truncated: boolean;
  dropped_kinds?: string[];
}

// FINDING_UNASSIGNED_ASSET corresponds to the backend's db.FindingUnassignedAsset.
export const FINDING_UNASSIGNED_ASSET = "__none__";

// ---- Activity / sessions ----
export type ActivityKind =
  | "tool_use"
  | "tool_result"
  | "text"
  | "thinking"
  | "result"
  | "user"
  | "intent" // LLM-generated exploration objective leading a worker session (UI-synthesized)
  | "round" // planner round boundary marker (engine-emitted)
  | "usage" // live cumulative token usage (per model turn); not rendered
  | "llm_switch" // automatic/manual task-level LLM switch
  | "llm_failover" // task-level provider switch / chain exhaustion audit event
  | "intercept_request"; // user-approval request from the intercept layer

// ChatAttachment is one uploaded file: path is relative to the session/task working directory (i.e. the agent's CWD).
export interface ChatAttachment {
  name: string;
  path: string;
  size: number;
  abs?: string; // absolute path (returned for scope=staging uploads; written into the description before the task is created)
}

export interface Activity {
  seq: number;
  intent_id?: string;
  worker: string; // session owner: planner | mainagent | work#1 ...
  ts: string;
  kind: ActivityKind;
  tool?: string;
  tool_use_id?: string;
  is_error?: boolean;
  summary: string;
  detail?: string;
  metadata?: {
    llm_transition?: LLMTransition;
  };
  source_task_id?: string;
  inherited?: boolean;
  main_seg?: number; // main-agent conversation segment (present only on worker="mainagent" rows)
  // token usage (present only on kind='result')
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface LLMAuditProfile {
  id: number;
  name: string;
  format: string;
  model: string;
}

export interface LLMTransition {
  mode: "automatic" | "manual" | "exhausted";
  reason: string;
  previous?: LLMAuditProfile;
  next?: LLMAuditProfile;
}

export interface TaskLLMResolution {
  profile_id?: number;
  name: string;
  format: string;
  model: string;
  source: "task_chain" | "agent_binding" | "global_profile" | "environment" | "global";
  available: boolean;
  reason?: string;
}

export interface TaskLLMResolutions {
  mainagent: TaskLLMResolution;
  planner: TaskLLMResolution;
  worker: TaskLLMResolution;
}

// ---- Agent triggers (P3 scheduling, custom agents only) ----
export interface AgentTrigger {
  id: number;
  agent_key: string;
  enabled: boolean;
  interval_sec: number; // timer: every N seconds (0 = no timer)
  on_finding: boolean; // fire when any task records a finding
  on_goal_met: boolean; // fire when any task meets a goal
  on_task_timeout: boolean; // fire when any task times out
  on_tool_call: boolean; // fire when a selected tool is called (on completion)
  on_task_create: boolean; // fire when any task is created
  interval_message: string; // separate user message for each trigger condition
  finding_message: string;
  goal_message: string;
  task_timeout_message: string;
  tool_call_message: string;
  task_create_message: string;
  tool_names: string[]; // tool keys selected for on_tool_call (at least one)
  last_fire?: string;
}

// ---- Conversations (chat page) ----
export interface ActiveFindingRetest {
  id: number;
  finding_id: string;
  conversation_id: number;
  status: "pending" | "running";
}

export interface FindingRetest {
  id: number;
  finding_id: number;
  conversation_id: number | null;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
  notes: string;
  summary: string;
  evidence: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Conversation {
  id: number;
  running?: boolean; // live server state, returned with the conversation list
  agent_key: string;
  title: string;
  llm_profile_id?: number;
  pinned?: boolean;
  pinned_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---- Backend logs (/logs page) ----
export interface LogLine {
  seq: number;
  db_id?: number; // server_logs.id; present for DB-persisted lines
  ts: string;
  level: "info" | "warn" | "error";
  tag: string;
  text: string;
}

export type SessionRole = "mainagent" | "planner" | "worker" | "system";
export type SessionStatus = "running" | "paused" | "done" | "blocked" | "exhausted" | "pending" | "stopped" | "deleted";

// Daily token aggregate bucket (GET /api/tokens/daily).
export interface DailyTokenBucket {
  date: string; // "YYYY-MM-DD"
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Per-worker token usage (GET /api/exploration/tokens).
export interface TokenUsage {
  worker: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface SessionTokenUsage {
  session: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface BatchControlItem {
  id: string;
  ok: boolean;
  status?: string;
  queued?: boolean;
  error?: string;
}

// Per-task result of a bulk category change. A failure can only mean the task was deleted; the category write itself is atomic.
export interface BatchCategoryItem {
  id: string;
  ok: boolean;
  error?: string;
}

// Whole-task (all agents) token aggregate.
export interface TokenTotal {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Global per-profile token spend from the llm_usage ledger (GET /api/tokens/usage).
export interface ProfileUsage {
  profile_name: string;
  calls: number;
  tasks: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// One (profile, UTC day) token bucket for the dashboard's daily chart (new source).
export interface ProfileDayUsage {
  profile_name: string;
  date: string; // YYYY-MM-DD
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
}

// Response of GET /api/tokens/usage — the dashboard's "new" (llm_usage) token view.
export interface UsageStats {
  by_profile: ProfileUsage[];
  daily: ProfileDayUsage[];
}

// Per-model token usage for one task (GET /api/llm/records/by-model), from the
// always-on llm_usage metering ledger. calls = number of LLM calls on this model.
export interface ModelTokenStat {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface Session {
  id: string;
  role: SessionRole;
  title: string;
  status: SessionStatus;
  live: boolean;
  last_activity: string;
  intent_id?: string;
  source_task_id?: string;
  inherited?: boolean;
  seg?: number; // main-agent session: which conversation segment (0 = original)
}

// ---- Security ----
export interface AuditEntry {
  ts: string;
  tool: string;
  action: "allow" | "block";
  reason?: string;
  command?: string;
}

export interface Audit {
  entries?: AuditEntry[];
  attributions?: Record<string, number>;
}

// ---- Traffic ----
export interface TrafficExchange {
  id: string;
  ts: string;
  host: string;
  method: string;
  url: string;
  status: number;
  content_type: string;
  resp_len: number;
}

export interface TrafficResp {
  enabled: boolean;
  proxy?: string;
  count?: number; // global total (unfiltered)
  total?: number; // rows matching the current filter (for pagination)
  page?: number;
  size?: number;
  exchanges?: TrafficExchange[];
}

// Full raw request/response of one exchange (lazy-loaded on row select).
export interface TrafficDetail {
  req: string;
  resp: string;
}

// One distinct recorded host with its exchange count (target picker).
export interface TrafficHost {
  host: string;
  count: number;
}

// ---- App settings (runtime toggles) ----
export interface Settings {
  traffic_capture: boolean;
  agent_traffic_binding: boolean; // agents automatically bind traffic evidence; off by default; does not affect manual binding
  llm_record: boolean; // LLM recording toggle (off by default); when off, no LLM calls are recorded
  // Web search. brave_key_set / tavily_key_set reflect whether a key is stored
  // (the values are never returned). On PUT, send the corresponding field to set/clear.
  web_search_enabled: boolean;
  web_search_backend: string; // "ddgs" | "brave-free" | "tavily" | "deepseek"
  brave_key_set: boolean;
  tavily_key_set: boolean;
  // write-only: only sent on PUT to store/clear the key.
  brave_search_api_key?: string;
  tavily_search_api_key?: string;
  // Dedicated egress proxy (http/https/socks5) for reaching search endpoints; unrelated to the MITM proxy that records traffic. Empty = direct.
  web_search_proxy?: string;
  // Global egress proxy (http/https/socks5, may include user:pass); all target traffic goes through it. When traffic capture is on it acts as the
  // MITM upstream; when capture is off it is injected directly into the agent's bash/WebFetch. Empty = direct.
  global_proxy?: string;
  python_interpreter?: string; // Python interpreter path for custom script tools (empty = detected at runtime)
  workers?: number; // number of concurrent worker agents (default 3); applies to tasks started afterwards
  // Task concurrency limit: the maximum number of tasks "running" at once. Off = unlimited; when on, new tasks over the limit are queued and start automatically when a slot frees up.
  task_concurrency_enabled?: boolean; // default false
  task_concurrency_limit?: number; // default 5 once enabled
  // LLM rotation (failover). Off by default; when on, agents with "no model specified" automatically switch to the next profile
  // when the current one is unavailable (insufficient balance / invalid key / rate limited / service fault).
  llm_pool_enabled?: boolean; // default false
  // Whether agents/tasks bound to a specific profile also fall back to the rotation chain on failure. Default false = binding is exclusive.
  llm_pool_bind_fallback?: boolean;
  // Scope of operational constraint injection (all on by default): splices the task's allow/deny constraints into the matching agents' system prompts.
  constraints_inject_planner?: boolean;
  constraints_inject_worker?: boolean;
  // Experimental: noa model-driven context compaction (off by default). When on, noa takes over context compaction for the four platform agent kinds (planner/
  // worker/main agent/chat), replacing the built-in compaction; read once per run, it applies to
  // runs started afterwards.
  noa_compaction?: boolean;
  // ---- Vulnerability IM notifications (channels are a separate resource, see /api/notify/*; only three global settings live here) ----
  notify_enabled?: boolean; // master notification switch, on by default; lets you stop everything at once during maintenance
  notify_public_base_url?: string; // external URL used for links back to vulnerability details; empty = messages carry no link
  notify_digest_interval_min?: number; // digest mode interval (minutes), default 30
}

// ---- Vulnerability IM notifications ----

// NotificationFilter is a channel's filter conditions; every field is optional and absent means no filtering.
// The backend does not validate any field: a malformed configuration is treated as a "match" (better to over-notify than miss one).
export interface NotificationFilter {
  min_severity?: string; // "" | low | medium | high | critical
  task_ids?: number[]; // empty = any; non-empty requires overlap with the vulnerability's task
  asset_ids?: number[]; // empty = any; non-empty requires overlap with the vulnerability's anchored assets
  vulnclass_include?: string[]; // empty = accept all; non-empty requires the vulnerability type to match any keyword (case-insensitive substring)
  vulnclass_exclude?: string[]; // excluded if any keyword matches (exclusion takes precedence over inclusion)
  on_status_change?: boolean; // whether to also receive vulnerability triage status change events
}

// NotificationChannel is a channel instance. The fields in config vary by kind,
// and credential fields are replaced on read with a mask value starting with "__masked__"; sending it back unchanged means "do not change".
export interface NotificationChannel {
  id: number;
  name: string;
  kind: string;
  enabled: boolean;
  mode: "realtime" | "digest";
  config: Record<string, unknown>;
  filter: NotificationFilter;
  rate_per_min: number;
  created_at: string;
  updated_at: string;
  // secret_keys is supplied by the backend per channel type; the frontend uses it to render password fields and the "leave blank to keep" hint,
  // without hard-coding any channel knowledge.
  secret_keys: string[];
}

// NotificationKind is the channel type metadata returned by /api/notify/meta.
export interface NotificationKind {
  kind: string;
  default_rate_per_min: number;
  secret_keys: string[];
}

export interface NotificationMeta {
  kinds: NotificationKind[];
  enabled: boolean;
  public_base_url: string;
  digest_interval_min: string;
  defaults: { digest_interval_min: number };
  stats: {
    channels: number;
    channels_on: number;
    pending: number;
    failed: number;
    sent_today: number;
    backlog_age_ms: number;
  };
}

// NotificationDelivery is one delivery record, used for delivery history and retrying failures.
export interface NotificationDelivery {
  id: number;
  finding_id: string;
  event_kind: string; // finding_created | finding_status_changed
  channel_id: number;
  channel_name: string;
  channel_kind: string;
  state: "pending" | "sending" | "sent" | "failed" | "skipped";
  attempts: number;
  last_error: string;
  batch_id?: number;
  created_at: string;
  sent_at?: string;
  next_attempt_at: string;
  title: string;
  severity: string;
}

// ---- LLM config ----
export interface LLMProfile {
  id: string;
  name: string;
  format: "openai" | "anthropic" | "openai-responses";
  base_url?: string;
  proxy?: string;
  model: string;
  api_key_hint?: string;
  rate_per_second: number;
  rate_per_minute: number;
  context_window_k?: number;
  // Thinking toggle (thinking.type): "" = not sent (default) | "disabled" = off | "enabled" = on
  thinking_type?: string;
  // Thinking effort: "" = not sent (default) | "low"/"medium"/"high"/"xhigh"/"max"
  reasoning_effort?: string;
  is_default: boolean;
  // Rotation priority: higher is chosen first. The active profile is always at the head of the chain, regardless of this value.
  priority?: number;
  // true = not used as a failover target (can still be bound explicitly by an agent/task).
  pool_exclude?: boolean;
  // true (default) = streaming (SSE) | false = true non-streaming (stream:false, returned in one go).
  streaming?: boolean;
  // Output limit for a single reply (tokens). 0 = field not sent; the server default applies.
  // Do not confuse with context_window_k: that is the model's total capacity and is only used locally for the compaction threshold.
  max_tokens?: number;
  // Which request field name the limit uses; only meaningful when format="openai":
  // "" = max_tokens (default) | "max_completion_tokens" (the only one OpenAI reasoning models accept)
  max_tokens_field?: string;
  // Custom session header name: when non-empty, every request carries this HTTP header with the current session/intent id as its value.
  // "" = not sent. For gateways that do prompt caching/sticky routing by a session-id header.
  session_header_key?: string;
  // This profile's retry overrides (connect / empty response / same-provider safe window). Blank/all 0 = follow the global policy.
  retry?: LLMRetryOverride;
}

// ---- LLM retry policy ----
// The two knobs for one retry layer. Both use "0 = not configured":
//   attempts    0 = default count | -1 = disable this layer | >0 = number of retries
//   interval_ms 0 = default exponential backoff | >0 = use this fixed interval in milliseconds
export interface LLMRetryRule {
  attempts: number;
  interval_ms: number;
}

// The three layers a single LLM profile can override (all retries that "follow the endpoint").
export interface LLMRetryOverride {
  connect: LLMRetryRule; // connect retry: connection reset/timeout/429/5xx, before the stream starts
  empty: LLMRetryRule; // empty response retry: completed with no content at all (openai format only)
  stream: LLMRetryRule; // same-provider safe window retry: replay of a dropped stream before any output was delivered
}

// Global policy = defaults for the three layers above + two layers that only exist globally:
//   breaker rotation circuit breaker (attempts = consecutive transient failures before tripping, interval_ms = fixed cool-down)
//   intent  intent rerun (rerun the whole intent after a worker ends with model_error)
export interface LLMRetryPolicy extends LLMRetryOverride {
  breaker: LLMRetryRule;
  intent: LLMRetryRule;
}

// ---- LLM rotation (failover) ----
// A profile's position and health in the rotation chain. state:
//   ok       healthy
//   degraded consecutive failures but below the trip threshold
//   tripped  circuit broken, skipped during cool-down (cooldown_secs is the seconds remaining)
export interface LLMPoolMember {
  profile_id: string;
  name: string;
  model: string;
  format: string;
  priority: number;
  active: boolean; // whether this is the active profile (always the head of the chain)
  excluded: boolean; // pool_exclude: not part of rotation
  state: "ok" | "degraded" | "tripped";
  fails: number;
  trips: number;
  cooldown_secs: number;
  last_error?: string;
  last_at?: string;
}

export interface LLMPoolStatus {
  enabled: boolean;
  bind_fallback: boolean;
  chain: LLMPoolMember[];
}

// ---- Agents ----
export interface Agent {
  id: string;
  key: string; // built-ins are goals/planner/mainagent/worker; custom agents use a user-defined key
  name: string;
  description?: string;
  role: string;
  builtin: boolean;
  enabled: boolean;
  llm_profile_id?: number | null; // bound LLM profile; null/absent = follow task/session/global
  max_turns?: number; // 0 = unlimited
  run_seconds?: number; // wall-clock limit for a single worker run (seconds); 0 = unlimited
  web_search?: boolean; // whether web search is enabled (gated by the global system switch)
  interactive_shell?: boolean; // whether the interactive shell is enabled (persistent PTY session tool family)
  // P3 post-trigger handling policy (only meaningful for custom agents)
  trigger_run_mode?: "serial" | "parallel"; // queue serially / each trigger runs its own concurrent session
  trigger_merge_mode?: "by_task" | "all" | "none"; // serial only: merge per task / merge all / do not merge
  trigger_max_parallel?: number; // parallel only: per-agent concurrency limit; 0 = unlimited
  // Binding counts (list endpoint only): visible MCP / visible skills / bound tools
  mcp_count?: number;
  skill_count?: number;
  tool_count?: number;
}

export interface PromptVar {
  name: string;
  description: string;
  example: string;
  source: "exploration" | "runtime" | "distilled";
}

export interface PromptVersion {
  version: number;
  ts: string;
  note: string;
  template_text: string;
}

export interface AgentDetail {
  agent: Agent;
  prompt: string;
  variables: PromptVar[];
  versions: PromptVersion[];
  visibility: { mcp: number[]; skill: string[] };
  // Candidate LLM profiles that can be bound (for the "default model" dropdown); the current binding is agent.llm_profile_id
  llm_profiles?: { id: number; name: string; model: string; is_default: boolean }[];
  wrapup_prompt?: string; // saved wrap-up prompt (empty = use built-in default)
  wrapup_default?: string; // built-in default wrap-up prompt (placeholder/restore default)
  wrapup_max_turns?: number; // saved wrap-up turn count (0 = use built-in default)
  wrapup_max_turns_default?: number; // built-in default wrap-up turn count (for the "0 = default N" hint)
  // Task-level timeout wrap-up prompt (worker/planner only; the section is shown only when task_timeout_wrapup_supported=true)
  task_timeout_wrapup_supported?: boolean;
  task_timeout_wrapup_prompt?: string;
  task_timeout_wrapup_default?: string;
  task_timeout_wrapup_max_turns?: number;
  task_timeout_wrapup_max_turns_default?: number;
}

// ---- MCP ----
export interface MCPServer {
  id: number;
  name: string;
  transport: "stdio" | "http" | "sse";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  enabled: boolean;
  insecure?: boolean; // http: skip TLS cert verification (self-signed servers)
  tools?: string[]; // mcp_tools_cache (names only, for the count)
}

export interface MCPTool {
  name: string;
  description: string;
}

// ---- Skills ----
// Fields align with the agentskills.io open specification.
// description covers both "what the skill does" and "when to use it".
export interface SkillItem {
  name: string; // unique key = directory name
  description?: string; // required per spec; covers what + when to use
  license?: string; // optional: SPDX identifier or free text
  compatibility?: string; // optional: environment requirements
  mcps?: string[]; // MCP server names this skill unlocks on load
  files: string[]; // files in the skill directory
  // Call statistics (skill_usage ledger). Skills that have never been called: calls=0, last_used absent.
  calls: number;
  tasks: number; // number of tasks that loaded it (chat sessions not counted)
  usage_agents: string[]; // keys of agents that loaded it
  last_used?: string;
}

// SkillCall is one Skill() call (the recent call list for a single skill).
export interface SkillCall {
  ts: string;
  agent_key: string;
  task_id: number; // 0 = not a task context (chat session)
  session_id: string;
  args_len: number;
}

// MissingSkill is a skill that was named but does not exist: a "wanted but missing" gap.
export interface MissingSkill {
  skill: string;
  calls: number;
  agents: string[];
  last_used?: string;
}

// ---- Tools (built-in tool catalogue) ----
// key + handler live in Go; only these fields are page-editable. system tools lock
// the key and the parameter *structure* (name/type/required) — the per-param
// description/default and the agent binding are what move.
export interface Tool {
  key: string;
  system: boolean;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema: Record<string, any>; // full JSON-Schema (object with properties)
  agents: string[]; // bound agent keys
  enabled: boolean;
  kind?: "builtin" | "shell" | "command" | "script" | "http"; // custom tool type
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec?: Record<string, any>; // custom tool execution spec (kind!=builtin)
  deferred?: boolean; // deferred schema (SearchExtraTools/ExecuteExtraTool)
  calls?: number; // persistent runtime invocation count (older APIs may omit it)
}

// ---- Stats ----
export interface Stats {
  assets: number;
  engine_mode: EngineMode;
  llm_configured: boolean;
  roe_enabled: boolean;
  findings_confirmed: number;
  active_task?: Partial<Task>;
}

// ---- Intercept Rules ----
export type InterceptAction = "allow" | "deny" | "ask";
export type InterceptMatchTarget = "tool_name" | "tool_input";
export type InterceptMatchType = "string" | "regex";

export interface InterceptRule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_target: InterceptMatchTarget;
  match_type: InterceptMatchType;
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
  created_at: string;
  updated_at: string;
}

// ---- Asset Intercept Rules (asset interception: global blocklist) ----
export type AssetInterceptKind =
  | "exact_domain"
  | "exact_ip"
  | "exact_url"
  | "fuzzy_domain"
  | "fuzzy_ip"
  | "fuzzy_url"
  | "cidr";

// action is only used by task-level rules: block = intercept (testing forbidden), allow = permit (allowlist).
export type AssetInterceptAction = "block" | "allow";

// Entry for task-level asset block/allow rules (used when creating a task and editing task details).
export interface AssetInterceptRuleInput {
  action: AssetInterceptAction;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  enabled: boolean;
}

export interface AssetInterceptRule {
  id: number;
  enabled: boolean;
  action?: AssetInterceptAction; // global rules omit this field (always block); task-level rules distinguish block/allow
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface InterceptPending {
  decision_source?: "rule" | "model" | "unknown" | "";
  id: number;
  rule_id?: number;
  conversation_id?: number;
  task_id?: string;
  agent_name: string;
  tool_name: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool_input: Record<string, any>;
  status: "pending" | "allowed" | "denied" | "timeout";
  reason: string; // rule message or model judgement reason (model judgements carry a [model] prefix)
  decided_at?: string;
  created_at: string;
}

// JudgeConfig: global settings for the model fallback approval (the model only decides when no intercept rule matches).
export interface JudgeConfig {
  enabled: boolean;
  profile_id: number; // 0 = follow the active/default profile
  prompt: string; // judgement prompt; when unset, GET returns the full built-in template from the backend
  timeout_seconds: number; // model call timeout
  fail_action: "allow" | "ask" | "deny"; // fallback when the model errors/times out/returns something unparseable
  ask_timeout_seconds: number; // approval wait timeout after the model returns ask and hands over to a human
  ask_timeout_action: "allow" | "deny"; // default action once approval times out
}

// JudgeUsage: cumulative token usage of the model fallback approval (judge channel) + a daily series for the last N days.
export interface JudgeDayUsage {
  date: string; // YYYY-MM-DD (UTC)
  calls: number;
  input_tokens: number;
  output_tokens: number;
}
export interface JudgeUsage {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  daily: JudgeDayUsage[];
}

export interface InterceptApprovalFilter {
  status?: InterceptPending["status"];
  decision_source?: "rule" | "model" | "unknown";
}

// InterceptApprovalRow enriches InterceptPending with conversation/task and rule context.
export interface InterceptApprovalRow extends InterceptPending {
  conv_title: string; // "" if no linked conversation
  conv_agent_key: string; // "" if no linked conversation
  rule_name: string; // "" if rule was deleted
}

// ── Asset sync (ScopeSentry data source) ──────────────────────────────────────────────
export interface SSProject {
  id: string; // MongoDB ObjectID — used as filter.project
  name: string;
  logo?: string;
  AssetCount?: number;
  tag?: string;
}

export interface SSTask {
  id: string;
  name: string; // used as filter.task
  status?: number;
  progress?: number;
  creatTime?: string;
  endTime?: string;
}

// ConvTokenSummary — one conversation's token total (+ profile/date) for merging
// chat usage into the dashboard token stats. GET /api/tokens/conversations.
export interface ConvTokenSummary {
  llm_profile_id: number | null;
  created_at: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// ---- Command recording (Bash execution history) ----
export interface CommandRecord {
  id: number;
  exploration_id: number;
  worker: string;
  tool: string;
  command: string; // raw tool input (JSON)
  output: string;
  is_error: boolean;
  created_at: string;
}

// Call statistics for a single tool (/commands/stats); errors is how many of those calls failed.
export interface ToolStat {
  tool: string;
  total: number;
  errors: number;
}

// ---- LLM recording ----
export interface LLMRecordItem {
  id: number;
  ts: string;
  model: string;
  profile_name: string;
  session_id: string;
  task_id: string;
  worker: string;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read: number;
  cache_write: number;
  status: string;
  error?: string;
}

export interface LLMRecordDetail extends LLMRecordItem {
  request_body: string;
  response_body: string;
  // The raw HTTP actually exchanged with the provider: the request is the full body sent by buildBody() (including the tool
  // schema); the response is the raw SSE frames. The request_body/response_body above are a normalised view that
  // drops the tool schema and tool_use blocks. Empty for older records.
  raw_request?: string;
  raw_response?: string;
}

// One distinct task with its LLM-record count (task picker on the records page).
export interface LLMTask {
  task_id: string;
  count: number;
}

// The exact JSON sent to the review model, retained for all model verdicts.
export interface InterceptReviewInput {
  version: number;
  background?: {
    // worker_summary is retained only for immutable v2/v3 snapshots.
    source: "user_message" | "worker_summary";
    text: string;
    truncated?: boolean;
  };
  // Version 1 snapshots are immutable and remain readable in historical audits.
  task?: {
    task_id: number;
    description: string;
    goal: string;
    constraints: { id: number; kind: string; text: string; origin: string; created_at: number }[];
    truncated?: boolean;
  };
  working_directory?: string;
  worker_intent?: string;
  turn_input?: string;
  background_truncated?: boolean;
  // Legacy v1/v2 snapshots only; v3 never sends execution history.
  history?: {
    tool_use_id: string;
    tool: string;
    arguments_preview: string;
    result: string;
    status: "succeeded" | "failed";
    truncated?: boolean;
  }[];
  history_truncated?: boolean;
  correlation?: "exact" | "ambiguous" | "unavailable";
  tool_name: string;
  arguments: Record<string, unknown>;
}

// Immutable review snapshot plus separately recorded execution outcome.
export interface InterceptAudit {
  model_input?: InterceptReviewInput;
  model_input_digest?: string;
  run_id?: string;
  tool_use_id?: string;
  correlation: "exact" | "ambiguous" | "unavailable";
  input_digest: string;
  user_message: string;
  user_truncated?: boolean;
  context:
    | { kind: string; tool?: string; tool_use_id?: string; text: string; is_error?: boolean; truncated?: boolean }[]
    | null;
  context_truncated?: boolean;
  captured_at: string;
  model_fallback?: boolean;
  initial_action: "allow" | "ask" | "deny";
  initial_reason: string;
  effective_action?: "allow" | "deny";
  decision_reason?: string;
  rule_name?: string;
  config_digest?: string;
  profile_id?: number;
  execution_status: "not_started" | "not_executed" | "awaiting_result" | "succeeded" | "failed" | "unknown";
  output?: string;
  output_truncated?: boolean;
  execution_ended_at?: string;
}
export interface InterceptDetail extends InterceptApprovalRow {
  audit: InterceptAudit | null;
}

export type TrafficEvidenceRole = "baseline" | "proof" | "verification" | "supporting";
export interface TrafficEvidenceRef {
  traffic_id: string;
  role?: TrafficEvidenceRole;
  note?: string;
}
export interface TrafficEvidenceSnapshot {
  id: string;
  source_traffic_id: string;
  captured_at: number;
  url: string;
  method: string;
  status: number;
  content_type: string;
  req_head?: string;
  resp_head?: string;
  req_hash: string;
  resp_hash: string;
  req_len: number;
  resp_len: number;
}
export interface FindingTrafficBinding {
  id: string;
  finding_id: string;
  snapshot_id: string;
  role: TrafficEvidenceRole;
  note: string;
  position: number;
  created_at: string;
  snapshot: TrafficEvidenceSnapshot;
}
export interface FindingTraffic {
  finding_id: string;
  version: number;
  report_version: number;
  bindings: FindingTrafficBinding[];
}
export interface EvidenceBodyPreview {
  content: string;
  offset: number;
  total: number;
  next_offset: number;
  truncated: boolean;
  binary: boolean;
}
export interface FindingTrafficDetail {
  binding: FindingTrafficBinding;
  request: EvidenceBodyPreview;
  response: EvidenceBodyPreview;
}

/** GET /api/update/check: comparison of the current version with the latest GitHub release. */
export interface UpdateCheck {
  /** The running version; development builds are "dev" or the suffixed git describe form. */
  current: string;
  /** Runtime form. Under Docker an upgrade only affects the container's writable layer; recreating the container reverts to the image version. */
  mode: "docker" | "binary";
  os: string;
  arch: string;
  repo: string;
  /** Whether a previous version is available to roll back to (artex.old). */
  has_backup: boolean;
  /** Outcome of the self-update bootstrap at this start-up (install failed / rolled back, etc.); empty when nothing happened. */
  boot_notice?: string;
  rolled_back?: boolean;
  /** The reason when querying GitHub failed; none of the fields below will be present in that case. */
  error?: string;
  latest?: string;
  notes?: string;
  html_url?: string;
  published_at?: string;
  /** The release package name for the current platform, and whether the release actually includes it. */
  asset?: string;
  asset_available?: boolean;
  size?: number;
  has_update?: boolean;
  /** Whether the two version numbers are comparable; false for development builds, in which case one-click update is disabled. */
  comparable?: boolean;
  /** Explanation when comparable is false. */
  reason?: string;
}

/** One update progress event pushed by /api/update/stream. */
export interface UpdateProgress {
  phase: "idle" | "downloading" | "verifying" | "extracting" | "staged" | "failed";
  /** Only meaningful during the download stage (0-100); -1 for other stages. */
  percent: number;
  message: string;
  version?: string;
  error?: string;
}

// Original execution selected from an approval, never submitted to the reviewer.
export interface InterceptExecution {
  conversation_id: number | null;
  task_id: string | null;
  session: string;
  seq: number;
  items: Activity[];
}
