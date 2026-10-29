# Changelog

Notable changes to this project are recorded in this file, in a format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Interception

#### Added

- **New built-in intercept rule "delete-type endpoint paths"**: the previous built-in HTTP destructive rules only recognised the DELETE **method** (`curl -X DELETE`, `requests.delete(`, `method:'DELETE'`), and the path-type rule's word list only had `/clear /wipe /flush /purge /truncate /drop /destroy /factory-reset /reset-all` — but most applications' delete endpoints can be triggered with GET/POST, so a call like `curl 'http://t/api/user/delete?id=1'` matched no built-in rule and would really delete target data. A `deny` rule is added covering `/delete /del /remove /unlink /erase /destroy` (allowing suffix forms like `/deleteAll`, `/delete_user`, `/delete-user`), where a separator must follow the verb, so `/delivery`, `/details`, `/delta` and `/delegate` are not intercepted by mistake. The rule uses its own seed flag, so **existing instances get it after upgrading**; like the other built-in rules it can be disabled or deleted under "System → Command interception".
### Vulnerability notifications

#### Added

- **Findings can be pushed to IM**: a new "System → Notifications" page can push scan findings to six channels — **DingTalk, Feishu, WeCom, a generic webhook, Telegram and email**. One type can have any number of bot instances configured (e.g. an "emergency response group" and a "daily broadcast group" each with a DingTalk bot), each with its own enable/disable, rate limit and filter rules.
- **Push timing has a realtime and a digest mode**: realtime sends one by one on a match; digest merges a batch of vulnerabilities into one message on a global window (30 minutes by default), opening with "M new vulnerabilities in the last N minutes" and a severity breakdown, so you can judge at a glance whether to act immediately. To do "critical in realtime, the rest in digest", create two channels configured separately; the policy is not hard-coded.
- **Filter rules support four dimensions**: a minimum severity level, limiting to a task / asset scope, vulnerability-type keyword include and exclude (exclusion takes precedence), and whether to receive triage status changes (off by default, since when most people say "notify" they mean a new finding, not a running log of status changes). A single message carries a "View details" button to the vulnerability detail, with the destination set by the global "link-back address"; leave it blank for no button.
- **Delivery history and manual resend**: the notifications page lists each delivery's status, attempt count, failure reason and channel, filterable by channel and status; a failed item can be resent in one click (which zeroes the retry count, since a manual resend means the failure cause has been dealt with).
- **Channel credential mask echo**: the webhook address, signing secret, bot token, SMTP password etc. are declared by each channel itself (`SecretKeys()`), and the API echoes only a mask value with a suffix hint; sending it back unchanged means "do not change", and clearing the input box deletes the field.

#### Fixed

> This section records the conclusions of a security-audit pass after the first version of the feature. Each item was reproduced, fixed, then covered with a regression test.

- **Fixed the mask being bypassable by "change the destination, keep the credentials" (critical)**: the masking mechanism's purpose is "credentials are not echoed to the browser", but the destination and the credentials are two independent sets of fields, and config merging keeps the stored value for any "key not mentioned". So **changing only the address and saying nothing about the credentials** could make the server send the real stored credentials to any address — the generic webhook's `Authorization` header, Telegram's bot token (in the request path), the email channel's SMTP password (handed to the peer after STARTTLS) all leaked, completely silently and without relying on a redirect. This path was shown to work, reproduced on each of the four channels. Now the rule is: **as soon as the destination changes, the caller must explicitly address every credential field** (give a new value, or explicitly leave it blank to say it is no longer needed) — sending the mask value back unchanged means "reuse the old credentials", which is exactly the attack shape and is rejected too. "Automatically dropping credentials" is deliberately not done, because for an optional credential field (such as `headers`) that would become "authentication silently gone but the API returns success", harder to diagnose than an error.
- **Fixed the markdown-family channels doing zero escaping of untrusted content**: DingTalk, WeCom and Feishu previously did no escaping at all (Telegram and email both did). The vulnerability title and summary come from model output (the model reads the target's responses), and an asset's `url` is a full URL obtained by scanning, with a target-controlled query string. A vulnerability titled `Login form SQL injection\n[URGENT: click here to verify your account](http://attacker.tld)` would render in a security engineer's DingTalk/Feishu as a **clickable external link**; `![](http://attacker.tld/beacon)` would be fetched by the client when rendered — announcing "this vulnerability has been viewed" and leaking the reader's IP. Now there is uniform single-lining + markdown metacharacter escaping. A related design error was also fixed: escaping must happen at each renderer's output, not in the title function shared by the four contexts (markdown escaping leaking into Telegram's HTML would leave visible backslashes).
- **Fixed the SSRF surface of delivery addresses**: previously only the scheme and host were checked, so `169.254.169.254` (cloud metadata, which can reveal instance credentials), loopback and internal addresses could all be delivered to; and on a failed delivery the first 200 bytes of the response body went into `last_error` and were echoed by the delivery history endpoint, forming a semi-blind read primitive (the first 200 bytes of any internal HTTP endpoint's response could be read). Now the defence is at the **dial stage** (not just validation at save time) — that is where it finally takes effect, and it also covers DNS rebinding and same-host redirects, and refuses cross-host redirects (these providers' credentials are in the URL, and following a redirect hands them to the redirect target). Loopback and link-local addresses require `ARTEX_NOTIFY_ALLOW_LOCAL=1` to be set explicitly (a local SMTP relay is a legitimate configuration and cannot be blanket-banned); **RFC1918 private networks are deliberately allowed**, because a self-hosted internal Mattermost / SMTP relay is common and defending that far would cripple normal deployments too.
- **Fixed notification credentials leaking via error messages**: on a failed delivery the `*url.Error` returned by `http.Client.Do` prints the **full URL** into the error text, and DingTalk's `access_token`, WeCom's `key`, Feishu's hook id and Telegram's `/bot<token>/` are **in the URL**. That string thus flowed to four outlets: `notification_deliveries.last_error` stored in plain text, the delivery history endpoint's verbatim echo (bypassing the channel config masking), the server logs, and the error hint the test-send endpoint returns to the frontend. Now there is uniform redaction — the error keeps only `scheme://host` and the underlying cause (enough to pinpoint DNS / connectivity / certificate problems), discarding the path and query. The error text of address validation itself (a `url.Parse` failure) also carried the full address and is handled the same way; **the previous round fixed only the former and missed the latter, and the regression cases then all took the scheme branch and never covered the parse-failure path — a false assurance** — and a case genuinely covering that branch has now been added.
- **Fixed silent loss from marking a whole batch delivered after a digest message was truncated**: channels have a length limit (WeCom's 4096 bytes is the tightest), and when a batch does not fit the message is truncated, yet on a successful send the whole batch was marked delivered — the truncated ones were **neither in the message nor in the failure list**, the delivery history still showed success, and the vulnerabilities simply vanished. Now it packs **by whole item**: only those that fit are marked delivered, the rest go back into the queue to continue in the next message, and the message header truthfully says "this message shows the first N, the remaining M follow in the next message". A deferred item **does not consume a retry attempt** (the optimistic +1 at claim time is subtracted back), otherwise a backlog of 500 would have its tail items judged failed at the third segment — though they never erred at all.
- **Fixed a typo in the minimum severity threshold making the filter fail silently**: when `min_severity` is mistyped (e.g. `hgih`), an unknown level has ordinal 0 in the table and the check degrades to `rank >= 0`, always true — the user thinks they limited it to "critical only" while actually pouring every vulnerability into the group, indistinguishable in the interface from a correct config. The value is now validated on the write path, with the error listing the valid values (the read path stays lenient: a bad value already in the database does not make a channel unreadable).
- **Fixed `rate_per_min = 0` (no rate limit) being unreachable**: the docs, the UI hint and the token bucket all interpret 0 as "no rate limit", yet this write layer alone had `if RatePerMin <= 0 { use default }`, quietly changing an explicit 0 to 20 (DingTalk/WeCom/Telegram) or 100 (Feishu) — the operator thought the limit was lifted while actually being held, with no hint. Only the request body can express the difference between "unspecified" and "explicit 0", so the default is now filled at the API layer when the field is absent.
- **Fixed the digest channel bypassing the token bucket entirely**: `allow` was deducted by `takeTokens` but used by no one, so `rate_per_min` had no effect in digest mode. The number claimed is now constrained by both "this round's quota" and the memory upper bound.
- **Fixed failure handling judging by the batch's maximum attempt count, so old deliveries dragged new ones down**: the attempt counts within a batch differ, and an old delivery already retried twice would drag a brand-new one in the same batch into failed — the new vulnerability lost forever without a single retry used, the opposite of "do not let old rows drag new ones down". The decision is now per item: a permanent failure is judged dead immediately, each one whose retries are exhausted is judged dead, and the rest are rescheduled at their own backoff tier.
- **Fixed a delivery whose snapshot cannot be parsed in a digest batch being silently marked successful**: such an item is skipped at the rendering stage (so it does not take the whole batch down), but was then marked delivered along with the rest. Now it is explicitly judged failed with a reason, and can be found in the delivery history.
- **Fixed a single channel's per-round delivery count possibly exceeding the lease duration**: the lease is 3 minutes, and if the number serially delivered in one round is large enough that the worst-case duration exceeds the lease, in a multi-instance deployment the peer re-claims the lease-expired rows, resends them and double-increments the attempt count. The per-round cap is now derived backwards from "lease / single timeout", with an assertion pinning the relationship of these three constants (writing that assertion immediately revealed the original value 6 used up the lease with zero margin, now adjusted to 5).
- **Fixed Telegram truncation possibly cutting an HTML entity**: truncation only avoided half tags, not a cut entity fragment like `&amp`, and the parser could reject the **whole** message because of it — overlong digest messages are common enough, so the cost is too high. Now it avoids both unclosed tags and entity fragments.
- **Fixed the email channel judging a temporary SMTP failure as permanent**: SMTP 4xx (such as greylisting `450`) is a temporary rejection and the proper response is to retry later, but it was all judged permanent — a mail server with greylisting enabled would put **every** notification into failed after the first attempt, exactly where automatic retries should work most. It is now distinguished by the first digit of the reply code: 4xx retryable, 5xx permanent, and treated as retryable when no code can be read.
- **Fixed a nested structure submission actually writing the mask literal into the database**: an object field like `webhook.headers` can only be masked or submitted as a whole; putting the mask sentinel inside the object can neither express "keep unchanged" nor be stored as a real value, which would make subsequent authentication fail silently with no error. Such a submission is now explicitly rejected.

#### Design notes

- **The vulnerability-writing transaction does just one blind INSERT**: `notification_events` is written by `RecordFindingTx` in the **same transaction**, and committing guarantees "the vulnerability is stored" and "the notification task exists" are atomically consistent. This INSERT deliberately reads no channel table and runs none of the user's filter rules — otherwise one misconfigured filter could pollute or even abort the transaction and stop a critical vulnerability being stored. To isolate a failure to this one statement (in PostgreSQL an error in any statement within a transaction voids the whole transaction and even `COMMIT` fails), it is wrapped in a `SAVEPOINT`, and on failure it is only logged and does not affect the vulnerability write.
- **Delivery is claimed with a lease rather than a long transaction**: after `FOR UPDATE SKIP LOCKED` claims a row it is set to `sending` and `next_attempt_at` pushed into the future as the lease, and the transaction is committed before the network delivery, so no database lock is held during delivery; a `sending` row left by a process crash is re-claimed on the next round once the lease expires, self-healing without infinite retries.
- **Rate limiting does not consume the retry budget**: the engine first works out how many more it can send this round from the channel token bucket, then claims that many. Reversing the order (claim first, drop later) would have a rate-limited delivery count one attempt for nothing, and once the three-attempt budget is burned by pure waiting it lands in failed. Exceeding the limit does not drop messages, only defers delivery to the next tick.

### Test infrastructure

#### Fixed

- **Fixed the cleanup order in the company ICP attribution case causing permanent asset residue**: the case registered cleanup in `t.Cleanup`, but closed the connection with `defer d.Close()` — `defer` runs first on function return and `t.Cleanup` after, so the cleanup statements all landed on an **already-closed connection**, their errors were dropped by `_, _ =`, and the test's assets and company stayed in the database forever. It uses `MAX(companies.id)+1` as a fake TaskID to tag assets, and once that number collided with another case's task id, that case's "exactly N assets" assertion would fail inexplicably and be very hard to locate. Now the connection close also goes through `t.Cleanup` and is registered first (last-in-first-out, so cleanup runs first), and a cleanup failure is surfaced rather than swallowed. The same pattern (`defer d.Close()` + writing the database in `t.Cleanup`) occurs in a dozen more places in the `db` package; only the one shown to be triggered was fixed this time.

### Traffic

#### Added

- **A "clear all" added to the traffic list**: deletes every traffic record at once, ignoring the current filter, and additionally cleans up historical host directories the index no longer records, leaving no residue. After clearing it also does a full compaction (`optimize` + `VACUUM` + `wal_checkpoint(TRUNCATE)`), returning the disk space the index occupied to the system, and reports how much was actually freed afterwards. Traffic evidence already bound to a vulnerability is kept in a separate evidence store and is unaffected. A `VACUUM` on an empty database is almost free, so this is also **the way for an existing instance to convert the index database to incremental-reclaim mode** — after one clear, everyday per-host deletion reclaims space on its own.

#### Fixed

- **Fixed disk space not being freed after deleting traffic**: deletion only made the data invisible, with the space staying in the index file. SQLite deletion only hooks pages onto the freelist, and the index database did not enable `auto_vacuum` at creation, so the file never shrank; meanwhile `ex_fts` is a `contentless_delete` full-text index where a `DELETE` only writes a tombstone and does not reclaim the original postings, accumulating forever without a merge — so deleting traffic actually made the index larger. Since bodies under 256KB are all inlined in this database, plus the trigram index at about twice the body size, an instance with heavy capture would occupy several times the disk for long-deleted traffic (in practice capturing 6MB of bodies → a 16MB index, still 16MB after deleting them all). Now a new index database enables `auto_vacuum=incremental` directly, and after each deletion commit it runs "full-text index incremental merge + `incremental_vacuum` + `wal_checkpoint(TRUNCATE)`" in the background in chunks, gradually returning the space to the operating system (dropping to 104KB after deletion in the same scenario). Reclamation runs in chunks and releases the write lock between them, not blocking traffic recording; it yields immediately on process exit, with the remaining work continued at the next deletion.

> Upgrade note: `auto_vacuum` can only be set at database creation, so **an existing instance's index database is still in the old mode**, where `incremental_vacuum` is a no-op — a line is printed at start-up to say so. For such a database the ongoing tombstone growth is already stopped after upgrade (the full-text index merge runs as usual), and the space already occupied can be reclaimed once with the traffic list's "clear all" — that step converts the database to incremental-reclaim mode, after which everyday deletion takes effect on its own.

### LLM

#### Fixed

- **Fixed the custom session header not taking effect on the "one-off LLM call" path**: the header value is taken from the session id on the request context, and that id is only written to the context by agentcore when a transcript store is attached. Goal decomposition (round 0) and cold-node compaction (the §4 body call) are both one-off calls with no store attached, so there is no session id on the context and the gateway cannot read the header — for an endpoint like opencode zen that returns "400 MissingSessionID without `x-opencode-session`", this showed as "round-0 goal decomposition 400 fails while later planner rounds are completely fine", with a compaction failure leaving only one log line, very hard to correlate. These two paths now explicitly attach a per-exploration-stable session id (`exp<N>-goals` / `exp<N>-compactor`): it both carries the header and lets llmrec attribute these two paths' token usage to the matching exploration correctly (previously it could not record it at all).

### Findings

#### Fixed

- **Fixed the "by asset" view's asset list having no scrollbar on overflow**: the left-hand asset tree already had a scroll container, but the outer card only gave a `max-height` and no definite height, and the scroll viewport could not resolve a height from `height:100%` (in CSS, a percentage height does not take effect when only `max-height` is set and `height` is still `auto`), so with many assets the list either burst the card or was truncated and unscrollable. The height cap is now placed directly on the asset tree's native scroll container (`overflow-y-auto` + `max-h`, adapting to the window height), so with few assets the card shrinks to its content and with many it caps out and shows a scrollbar.

## [0.3.14] - 2026-09-24

### Task list

#### Added

- **A "Vulnerabilities" column added to the task list**: shows the critical / high / medium / low counts by severity, with non-zero buckets coloured by severity, so each task's vulnerability scale and distribution is clear at a glance.

#### Changed

- **The "Description / Goal" columns are narrowed**: overly long content is ellipsised with the full text on hover, to reduce long text taking up the list's horizontal space.

### Exploration graph and planning situation overview

#### Changed

- **Streamlined the planning situation overview (graph_overview) and set count caps on each list**: recent facts, ended intents, pending intents, cold-region digests and the confirmed-vulnerability details are all changed to "the latest window + a count fallback", with what is not shown queryable on demand; this significantly reduces each round's LLM context size and avoids long-task context bloat (the cold region of a related-task overview is rate-limited too).

#### Fixed

- **Removed the reverse duplicate edge between a digest and a finding in the exploration graph after cold nodes are folded**.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.13] - 2026-09-19

### Asset interception

#### Added

- **New global asset interception rules (blocklist)**: supports entering exact and fuzzy domain / IP / URL matches as well as CIDR ranges, with create/read/update/delete and enable/disable of rules, on the "System → Asset interception" page; it ships with built-in fuzzy interception of government (`.gov` / `.gov.cn`) and education (`.edu` / `.edu.cn`) sites by default.
- **Asset interception wired into the execution chain**: before an agent issues an intent (`add_intent`) or inserts an asset (`insert_assets`), it runs an interception decision on the target asset — an intent that matches interception is not issued, an asset that matches is not inserted, and the asset info and interception reason are returned to the agent.
- **New task-level block / allow (allowlist) rules**: independent of the global rules and applying only to this task, with a decision order of "block first then allow" — a block match forbids it; no block match but the task has allow rules configured and none match means "testing not allowed"; with no allow rules the allowlist is not enabled. They can be entered at task creation, and added/edited/deleted and enabled/disabled in the task detail's "Overview".
- **Task templates support preset categories and task-level block/allow rules**: a template can save a task category and a set of task-level rules, which are brought into the new-task form when the template is applied.

### Operation review

#### Fixed

- **Tightened the model judge's output protocol to reduce false allows from truncation**: lowered the verdict comment cap from 500 characters to 120 and enforced "output only JSON, no preamble or code block", to avoid a verdict that cannot be parsed after being truncated by `MaxTokens` and then allowed under the model-failure policy (fail-open).

### Task archiving

#### Fixed

- **Skip a symbolic link during archiving rather than failing the whole package**: the archive format supports only regular files and directories end-to-end, and previously any symbolic link in the working directory would fail the whole task archive; now the symbolic link is skipped and logged, with the other files archived as normal (the link is not followed and the directory tree is not escaped).

### Account and compliance

#### Added

- **A "terms of use and disclaimer" dialogue added before login**: it must be agreed to before logging in.

### Licence and dependencies

#### Changed

- **The project adopts the AGPL-3.0 open-source licence**, with the README's licence and disclaimer notes completed.
- **Upgraded norma to v0.4.1**.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.12] - 2026-09-17

### Exploration-chain broadcast board

#### Added

- **A "exploration-chain broadcast board" added to the task detail page** (#144): presents the task's exploration nodes (start/goal/intent/fact/vulnerability/hint/compaction) as a timeline stream, with filtering by type, keyword search, ascending/descending order, paging and auto-refresh; at the "page 1, newest first" position it is the live spot and refreshes every round, and when away from it only the unread count accumulates without disturbing the current reading, with a "N new broadcasts · back to latest" one-click return. Grouped by day, so even paging through a long task you can tell "which day this happened".
- **The broadcast board shows a node id on each row** (#145), to cross-check against the exploration-chain graph and locate a specific node.
- **Expanding a broadcast node's detail shows its upstream/downstream and anchored assets** (#147): expanding a broadcast shows that node's upstream (where it came from) / downstream (what it produced) relations, and hovering a related entry pops up that node's card (type/status/source/time/summary/payload excerpt); it also lists the assets the node anchors (type label + identifying text). The data is sent with the broadcast page, so expanding makes no extra request.
- **The broadcast board's search supports filtering by node id** (#150): the search box adds a node-id match besides "content / source", and entering a plain number or the "#41" form shown in the interface locates the matching node exactly.

### Intent management

#### Added

- **Intent deletion supports "soft delete / hard delete"** (#149): an intent awaiting claim, running or paused can be deleted, deletion requires a reason, and the mode is chosen in the confirmation dialogue.
  - **Soft delete (default)**: the intent is set to "deleted" and the reason recorded in a separate field, keeping the intent node and all its output and lineage.
  - **Hard delete**: physically removes the intent and the exclusive descendant nodes "supported only by it" (cascading to the leaf along the output / intent chain), to avoid leaving orphaned data; the deleted intent's token metering is archived by its original date; shared nodes (still referenced by other intents), goals and the task root fact are all kept, and the hard-delete dialogue shows the estimated number of nodes affected by the cascade.

  Both modes notify the planner "this intent was deleted by the user + the reason" and re-plan accordingly.

### Operation review

#### Added

- **Approval records support filtering by status and decision source** (#139): approval records can be filtered by approval status and decision source, to locate a target record quickly.

#### Fixed

- **Pending approval requests load independently of the history paging** (#133): pending requests are no longer affected by the history list's paging, and stay fully visible while browsing the history.

### Agent

#### Changed

- **The Worker role description changed to a generic cybersecurity-platform wording** (#138).

#### Fixed

- **Fixed cold-node compaction never triggering**: the Compactor is wired into the per-task planner, and cold-node compaction (cold-digest), previously never run because it was not wired in, is now restored.

### Chat

#### Added

- **Chat supports @-mentions of multiple record types with scroll paging** (#135): several record types can be @-mentioned in chat, and the mention candidates support scroll paging.

#### Fixed

- **Long message bubbles are constrained within the conversation panel** (#137): an overly long message bubble no longer overflows the conversation area.
- **Fixed "missing upload file" when uploading before a new conversation is created**: the Composer's file selection snapshots the `FileList` into an array before clearing the input and then calls back; previously a draft state had to create the session asynchronously first, and by the time it resumed the `FileList` live-bound to the input had been cleared, so the upload was missing the file field and the backend returned 400.

### Traffic

#### Fixed

- **The traffic recording proxy listens only on 127.0.0.1 by default** (#129, #130): to avoid the default config exposing the open proxy on other network interfaces.

### Web

#### Fixed

- **Fixed the static-export task list page losing the global header**.
- **Completed the demo vulnerability detail page's linked-traffic mock, fixing a blank screen**.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)
- [@dingpotian](https://github.com/dingpotian)

## [0.3.11] - 2026-09-15

### Operation review

#### Added

- **Approval records support source location** (#125): clicking an approval record's "source" jumps back to the tool execution that triggered that approval — opening the original full session, auto-paging to the target position, expanding the command and result in place and centring and highlighting it in the scroll area, with the surrounding messages kept readable; auto-correction stops when the user scrolls manually. Across ordinary conversations, task Workers, the planner and main-agent segmented sessions, it locates precisely via the persisted `tool_use_id` and task mapping (a new within-scope call-id index), and hints explicitly when it is missing, duplicated or ambiguous rather than jumping to another execution. A clear hint is given when the session is deleted or the task is archived/the record is missing.
- **Approval records support paging** (#115).

#### Changed

- **Streamlined the model review input** (#124, #125): the model review (the LLM judge after no rule matched) input is narrowed to a versioned JSON of "the current complete tool call + an explicitly selected short background + the local working directory". The background takes only a real user message (the current user message of a chat/task main agent), the Worker no longer carries an intent summary and the background inherited from a parent agent is cleared; the planner and auto-triggered sessions invent no user message. It no longer carries the task description, goals, operational constraints, the global exploration situation, historical calls or the Worker's full intent — these are still used for agent execution and independent session auditing as before, just not fed into the operation review. Every verdict requires outputting the `decision`/`comment` JSON, and the comment must contain "the action, the consequence, the matched rule"; instructions in the parameters or background cannot change the review policy. The snapshot and fingerprint of the input actually sent to the model are saved, with older snapshots kept and version-tagged, and old inputs are not invented from current data.

#### Fixed

- **A model verdict wrapped in a code block is no longer silently allowed** (#126): if the model's verdict JSON was wrapped in a ``` code block, a parse failure was previously silently allowed under the model-failure policy; now the code fence is stripped before parsing, and the configured failure policy applies only if parsing still fails.

### Agent

#### Added

- **New experimental noa context compaction** (norma upgraded to v0.4.0): an experimental feature toggleable in system settings, off by default. When on, noa (model-driven context compaction) takes over context compaction for the four agent kinds — main agent, planner, Worker and chat — replacing the built-in compaction; the compressed originals are persisted and archived centrally under `<workDir>/noa/<session ID>/` (not scattered across task directories), in a globally unique directory per session ID. A wiring failure automatically falls back to the built-in compaction without interrupting a real task; the switch is read once per run, so switching only affects runs started afterwards.

#### Fixed

- **Exploration-graph tools refuse rather than crash on nil with no task context**: calling an exploration-graph tool outside a task context returns a clear error, no longer crashing on a nil-store dereference.

### MCP

#### Added

- **Support for legacy SSE MCP services** (#117): compatible with an MCP server that only offers the old-style SSE transport.

### Traffic

#### Fixed

- **Traffic search matches a record's host port-awarely** (#114): `traffic_search`'s host match includes the port, to avoid same-host records on different ports cross-contaminating.
- **A `traffic_search` description migration error no longer interrupts the later reporter migration**: a single migration failure is isolated and does not affect later migrations.

### Web

#### Changed

- **A divider added to the task retest vulnerability options** (#122): a separator between retest vulnerability options for a clearer look.

#### Fixed

- **Fixed the demo task detail page crashing the whole page**: in mock mode the task detail's "Sessions" tab would fetch `GET /api/tasks/<id>/side-questions` (the side-question history), but the mock handler had no such route and the read fallback, treating "a path ending in s as a collection", returned `[]`, making `data.items` `undefined`, so the side-question hook's `merge()` threw `TypeError: t is not iterable` iterating it; that exception happened in `setItems`'s updater, deferred by React to the render phase and rethrown, where the caller's `catch` could not catch it, and the whole page was taken over by the error boundary showing "This page couldn't load". Now the mock handler explicitly returns an empty side-question history, and `sideAPI.history` also normalises the return (any non-array `items` falls back to `[]`) as defence in depth.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.10] - 2026-09-13

### Network

#### Added

- **Web search gains an official DeepSeek source**: it directly reuses the current active LLM profile. It differs in nature from the other three sources — DeepSeek has no directly callable search endpoint, and search exists only inside its Anthropic-compatible interface (the `web_search_20250305` server tool), executed by DeepSeek's server. So it **only supports the official DeepSeek endpoint + the anthropic protocol** (an OpenAI-protocol endpoint rejects the server tool), each search **consumes an extra model call**, the request **does not go through the search egress proxy** and **is not recorded in the traffic trail**, and the result has **only a title and link** (no summary; use WebFetch for the body). The settings page explains these limits but **does not validate/block**, leaving it to the user to confirm, with a "test search" button to run one for real.

### Agent

#### Added

- **The worker gains cross-work review**: new `search_all_worker_traces` (no need to know the intent_id first; search all this task's works' execution processes globally for matching steps by keyword) and `get_worker_trace` (once a work is pinned, list its step stream, search it in place by keyword, and fetch full content by step_id), to reuse observations another work saw but did not write into a fact and avoid duplicate effort.
- **`node_detail` is given to the worker**: together with the review tools above, once the worker has an intent_id / node id it can query that node's full detail directly.
- **A planning round triggered by `add_hint` is explicitly broadcast**: previously a new hint only folded into the situation overview for the planner to find itself; now one `add_hint` records a "the person added N strategic hints: …" trigger for the planner (a batch counts as one, not flooded one at a time), and the planner is explicitly told "this round was triggered by new hints" and sees the hint content directly.

#### Changed

- **The global situation hint changed to a "loosening" tone**: it encourages diverging exploration and reporting cross-intent leads promptly, rather than converging too early.
- **Streamlined the worker's boundary wording**: an initial setback does not mean exploration is complete, with a focus on "finish this intent's bypass approaches before concluding".
- `insert_assets` removes the per-asset `related` parameter: its only job was to decide whether to add this asset to the task scope, its value is not stored (it is void when the asset is registered again, and the interface cannot show who was judged unrelated), and in practice it just made the model do one more judgement it could not keep.
- **The test scope (`task_scope`) is no longer affected by the asset coverage switch**: `insert_assets`'s auto scope addition (`source='auto'`) runs whether or not coverage is on, and `add_task_scope` is always provided to the planner / in-task main agent / goal-decomposer agent. The scope is the task's authorisation boundary and the filter basis for asset queries; the coverage switch only decides whether to use it as the denominator for metrics, and should not decide whether to accumulate the scope itself. Previously turning coverage off disabled both the `auto`/`agent` write paths, leaving `task_scope` with only rows added by hand in the interface. `list_untested_assets` is still hidden when coverage is off (it is itself a pure coverage view).

#### Fixed

- **Fixed assets crossing over between tasks** (#59): `list_assets` previously hard-coded the task id to 0 and queried the whole shared asset store bare, with the model unable to write a scope filter, so it treated another task's assets (especially IPs) as this task's targets and skewed the test direction. Now it returns only assets within the test scope (`task_scope`) of [this task and directly related tasks], matching by **ownership** rather than literal value: a root domain in scope finds all its subdomains/services/endpoints, a network range finds the hosts and services within it; fetching an out-of-scope asset by id likewise finds nothing. A non-task context (Auto/pentest) has no scope to rely on and still falls back to the whole store. It also fixes the attribution blind spot where an IP-direct host (such as `http://1.2.3.4/api`) could not be matched by a network-range scope. The UI's "test assets" view (filtered by the task producer) is unaffected.
- **Fixed the worker's cross-work review tools being removed by mistake**: after `search_all_worker_traces` / `get_worker_trace` (and `node_detail`) were added to the worker's default tool set, an old "narrow the worker tool surface" migration unbound them again at start-up, so the worker did not actually get these tools. They have been removed from that unbinding list, and a one-off rebind to the worker added for databases that already ran the old migration.
- **Fixed occasional storage failures of `/btw` side questions**: the side_question checkpoint strips the JSONB-unsupported NUL (`\u0000`) escape before storage, to avoid an error writing content containing that character.

### Triggers

#### Fixed

- **A merged trigger session de-duplicates the task description/goal per task**: on a multi-task merged trigger, the same task's description/goal is no longer spliced into the message repeatedly, to avoid a long goal stacking repeatedly and bursting the context.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.9] - 2026-09-11

### Agent

#### Added

- The in-task main agent supports **multiple sessions**: you can create, switch and reset the context independently, and every session is interactive.
- Support for persistent `/btw` **side questions**: follow-ups that do not interrupt the main line, with the Q&A stored and still present after a restart.
- `spawn_task` gains `source_task_ids`, so a new task can **inherit, read-only**, a source task's assets and findings.

#### Changed

- Turned off the worker's cross-engagement memory and narrowed its default tool surface: reading context and cross-work review are planning responsibilities, and the worker only handles the execution and write-back of a single intent.
- Streamlined the worker's default prompt; `get_worker_output` drops the `terminated` and `worker_name` fields; streamlined the descriptions of `insert_assets` / `list_assets`.

#### Fixed

- Fixed a work being cut off early by an **idle turn**: the model sometimes uses a whole turn outputting only thinking, giving no body and calling no tool, and the harness sees this as a natural end (`end_turn` with no `tool_use`) and finishes with `completed` + an empty summary — an intent not yet finished is cut off half-way, showing as "the task ended normally but with no text summary at all". None of the five LLM retry layers can reach it: it is not an error, the same-provider safe-window retry's entry is a "stream failure", the circuit breaker judges success on `err == nil`, and intent rerun only recognises `model_error`; the SDK's empty-response retry cannot reach it either, because that layer judges empty by "whether any event was yielded", and a thinking delta is itself an event. Now the work's Stop hook recognises this turn and injects a continuation instruction, so the model carries on with the thinking it has produced — "resend as-is" is deliberately not chosen, because such idle turns are usually determined by the prompt and context shape, a stable behaviour rather than a random hiccup, and resending would only make the model think it over again.
- The count reuses the **empty-response retry count** from the LLM page's "Retry and backoff" (both answer "the model finished but produced no real content", just with different criteria and means), defaulting to 2, and setting `-1` turns it off and returns to the old "finish on an idle turn" behaviour. It is a **total** cap for one intent, not a consecutive count: the harness already limits a run of idle turns to one nudge, and the quota only refreshes once a genuine tool turn has happened, so this number guards against a "tool → idle → nudge → tool → idle" loop draining the intent's budget. On trigger the log records `[work <worker> · #<intent>] idle turn… injecting a continuation instruction (n/N)`. See `docs/llm-retry-design.md` §1.1.
- Fixed the `/btw` context budget and input layout for long conversations; degrade to generating a side-question request ID in an insecure context (non-HTTPS access).

### Traffic

#### Added

- A vulnerability can **link multiple traffic evidence items**, orderable, with notes, distinguished by role (request/response/supporting).
- The reporter agent **automatically links** the relevant traffic evidence before writing the report.
- A new agent **traffic-binding switch**, with the evidence handover between agents completed.

### Tasks

#### Added

- Support for **session-level vulnerability retest**: the retest runs in an independent agent session, with the run state shown in the list and detail.

### Interception

#### Added

- Approval records gain a **detail and execution audit**: you can view the tool request context, the model/rule initial judgement, the execution output and the parameter fingerprint.

### Assets

#### Added

- Task test assets support **DSL search**.

### LLM

#### Fixed

- Fixed the connection test not sending the custom session header, causing opencode zen to return 400.

### Network

#### Added

- The MCP HTTP transport supports **skipping TLS certificate verification**, for connecting to a service with a self-signed certificate.

### UI

#### Added

- The session list is grouped by agent, with expand/collapse and independent pinning; conversations can be filtered by agent.
- The attack-chain graph renders compaction (digest) nodes and collapses their members.

#### Fixed

- Fixed a blank screen caused by login credentials being out of sync.
- The interception hint text was changed to clearly state "platform control", to avoid being misread as a target-side defence.

### Deployment and updates

#### Added

- Support for **web UI one-click update**: a "Version and updates" card is added to the system config page, and the top bar shows a hint when a new version is available. The flow is: download the release package → verify `SHA256SUMS` → smoke test → stage → exit, with the supervisor script relaunching to complete the swap, and the page refreshes automatically.
- New supervisor launch scripts `start.sh` / `start.bat` as the formal launch entry point (included in both the release package and the Docker image; `install.sh` is unchanged), deciding whether to relaunch from the exit code and forwarding SIGTERM to artex. The verification and swap logic are all in Go, and the scripts stay simple.
- Automatic fallback on failure: if verification or the smoke test fails it is discarded and the current version keeps running; if a new version fails to start 3 times in a row it rolls back to the previous version. The settings page also has a manual rollback (note the database structure does not roll back).
- Updates only trust GitHub domains and force HTTPS, the release source is not configurable, and development builds disable one-click update. GitHub query results are cached for 30 minutes, to stop the top-bar hint exhausting the API quota.

#### Known limitations

- Under Docker only the program is swapped, not the image: the toolchain is not upgraded with it, and recreating the container reverts to the image's own version, so use `docker compose pull artex` when needed.
- The `skills/` inside the release package is not synced, so a built-in skill added in a new version does not take effect automatically.
- An update means a restart, which interrupts a running task.

### Dependencies

#### Changed

- Upgraded norma to v0.3.7.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@RuoJi6](https://github.com/RuoJi6)

## [0.3.8] - 2026-09-09

### LLM

#### Added

- A "Retry and backoff" tab is added to the LLM page: the **count** and **interval** of all five retry layers are configurable. A model call's failure goes, from inside out, through connect retry (SDK, a connection reset / timeout / 429 / 5xx before the stream starts), empty-response retry (SDK, a normal end with no content at all, openai format only), same-provider safe-window retry (replaying a dropped stream before any output is delivered to the caller), rotation circuit breaker (cool down and skip after consecutive failures reach the threshold) and intent rerun (rerun the whole intent after a worker ends with model_error), with the outer layer taken only when the inner is exhausted. Each layer has two knobs with uniform meaning: blank = use the original default count and exponential backoff; a count uses that count; an interval replaces the exponential backoff with a fixed interval; -1 turns the layer off. The first three follow the endpoint and can override the global default per field in each model profile (setting only the interval still inherits the global count); the circuit breaker and intent rerun are process-level and exist only once globally. They take effect hot after saving, with no restart. All blank is the current behaviour, byte-for-byte unchanged after an old database upgrade (the new columns default to 0, and an absent settings key means all defaults). The connection test deliberately does not carry these parameters — it has a 30s hard timeout, and layering the user's retries on top would only make a usable endpoint test as a timeout failure. See `docs/llm-retry-design.md`.
- Each LLM profile supports a custom **session header** (`session_header_key`): when non-empty, every LLM request carries this HTTP header with the current running session id as its value (a chat session is `conv-<id>`, a worker `exp<x>-worker-i<intent>` etc.), for gateways that do prompt caching / sticky routing by a session-id header. It is implemented by reading the session id from the request context and injecting it, with no norma change, and even one shared provider can send different header values per session. The old database gets a migration, and a new input box is added to the frontend LLM config dialogue.

#### Fixed

- Fixed saving an LLM profile reporting `23502` because the session header field was empty: that column is `NOT NULL DEFAULT ''`, and previously a mistaken `NULLIF($n,'')` wrote an unfilled session header as NULL and triggered the not-null constraint; it now passes the argument with empty-string semantics.

### Agent

#### Added

- The wall-clock timeout changed to **wrap up in place**: relying on norma v0.3.6, when `MaxDuration` is due it interrupts the running tool and continues on the live ctx for the wrap-up turns (writing back what was identified + a summary, with the terminal state timeout), no longer relying on the worker/planner's own `maxDur+90s` external hard ctx to kill a stuck run outright into `aborted_tools`. Chat, going through the same harness, automatically gets the same behaviour, and mainagent, with no `MaxDuration`, is unaffected.
- Stall fallback: when the planner wakes on a heartbeat / with no change and the whole graph has no open or running intent, the opening line changes to a stall warning, clearly stating no worker is running and no direction is queued, so this round must produce one or more mutually non-duplicate new intents (and must not produce 0).

#### Changed

- The worker prompt was restructured: the intent / launch instruction / anchored-asset raw JSON moved into the system prompt, reassembled every round and never compressed away by compaction, so resuming does not depend on the transcript's first message being kept; the launch user message is slimmed to only the global situation overview (degradable, tolerating being stale). The cost is that system mixes in per-intent data and loses cross-intent cache reuse, a deliberate trade-off for "not losing the intent".
- Streamlined the planner / worker default bodies and fixed several real-world issues: the planner distinguishes `recent_done` by state (for blocked/exhausted it checks the trace before deciding, treating it as neither a dead end nor a blind rerun), negative conclusions become "an observation / doubtful, not settled" and are checked against evidence before being trusted, a goal unmet with no open/running intent must produce (the hard line), and depth over coverage; the worker writes a negative conclusion only as "an observation + a tentative reading" with the decision left to the planner, writes a cross-intent lead into a fact's summary for the planner, and does not chase it itself. Reseed appends the new default as a new version and switches to it, keeping user customisations / old versions in history for rollback.
- Narrowed the work agent's default tool set and asset write-back hints: the worker only handles the execution and write-back of a single intent, and reading context / cross-work review are planning responsibilities, so `list_facts` / `node_detail` / `list_companies` and cross-work search (`search_all_worker_traces` / `list_worker_traces` / `get_worker_trace`) are removed from its defaults, keeping only `list_findings` (de-dup before reporting) + `add_finding` / `record_fact` + `insert_assets` / `list_assets`; the prompt drops the stale field descriptions that clashed with the `insert_assets` schema (`type=tech`/`on_url`/`props`). The old database gets a one-off migration to strip the matching bindings, leaving planner/main's same-named bindings alone.

### Exploration graph

#### Added

- **Exploration-graph cold-node compaction (cold-digest)**: folds old, long-inactive intents / facts into a digest node shown in `graph_overview`, with the original nodes kept permanently and fully restorable by id (lossless storage, compressing only the presentation, foldable and reversible). Hot/cold is judged by reverse reachability + any live branch meaning hot, with R=6 rounds of debouncing and connected-component grouping; the background compaction (minor folds uncovered cold blocks, major re-folds from source to merge fragments) has an activity recheck and a cool-down mutex, and never goes on the hot path nor overwrites a revived node. The overview side provides `cold_digests` and an asset-indexed `cold_index`, with `expand_digest` / `expand_index` restoring them. A related / inherited task's overview likewise reuses its own folded view, and `expand_digest` supports cross-task read-only restoration. `expand_digest` / `expand_index` are given to the planner and main agent only, not the worker. All come with an old-database migration.
- `graph_overview` outputs `finding_list` in full: findings are the task's highest-value output and usually few per task, so it is changed to carry them all in the overview (unlike facts, which give only a recent window), letting the planner/worker see every confirmed vulnerability at a glance each round without calling `list_findings`. Each is slimmed to `{id, summary, evidence?, from_intent?, assets?}`, where the affected assets are given as readable content (url / domain / ip:port) rather than a bare id.

#### Changed

- `graph_overview` no longer flattens `hosts`: the coverage block drops the host list (in a large-scope task it carries up to 500 host strings each round, of limited value for planning decisions), keeping only `host_count`, with specific hosts queried on demand with `list_assets`. A top-level `done_intents_total` (the total number of ended intents) is added, parallel to the `recent_done_intents` truncated to ≤15, so the planner knows whether there was truncation when de-duplicating.

### Tools

#### Changed

- `add_company_scope`'s default binding changed from worker to planner: defining a company's asset scope is the job of planning / main / Auto, and the worker only executes exploration. A new database seeds the default binding as mainagent/planner/auto, and the old database gets a one-off migration.
- The planner is bound to `list_assets` by default: it now has both `list_assets` (DSL whole-store search) and `list_untested_assets` (untested within scope), with a one-off backfill for the old database that does not override a user's unbinding.

### Tasks

#### Added

- A "running Workers" column added to the task list: counts the task's intent nodes with `state='running'`, measured exactly as the "running Workers" in the task detail page's overview, showing 0 when there is no running Worker.

### Network

#### Added

- New **global egress proxy** config: all target traffic can egress through a unified global proxy (http/https/socks5, with `user:pass` support). With traffic capture on it acts as the MITM proxy's upstream (traffic is still recorded then egresses via the proxy, and both the intercept and pass-through paths go through the upstream without leaking the source IP); with capture off it is injected directly into the agent's bash environment and WebFetch (`proxyEnv` adds `ALL_PROXY` for socks5). The config is stored in the settings KV table (no migration needed), and the frontend system config page adds a "global proxy" card, independent of the web-search proxy and the LLM proxy.

### UI

#### Fixed

- Corrected the semantic errors of the intent status labels: `exhausted` "exhausted" → "budget exhausted" (it is actually cut off mid-way on reaching the step / time budget, writing back only partial results, not that the direction is fully explored), `blocked` "intercepted" → "execution error" (it is actually the model / API / network failing with retries exhausted, so the intent basically never genuinely explored, not a target / WAF block), and added the previously missing `stopped` "stopped" (a work the user manually stopped).

### Dependencies

#### Changed

- Upgraded norma to v0.3.4: MCP tool output gains truncation and spill-to-disk (see `651b961`), and the later v0.3.6 supports the wall-clock wrap-up in place.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.7] - 2026-08-31

### LLM

#### Added

- Model profiles gain an "output cap", with an optional choice of which request field name the cap uses: the cap limits how many tokens a single reply generates at most and is sent with every request, where 0 (default) = do not send the field and let the server default decide; it is a different thing from the "context window" — the latter is the model's total capacity, used only locally to compute the compaction threshold and not present in the request. The field-name switch only matters for the `openai` (Chat Completions) format: blank (default) sends `max_tokens`, which almost all compatible gateways accept; OpenAI's official reasoning models (the o-series / GPT-5) conversely accept only `max_completion_tokens` and return `unsupported_parameter` on receiving `max_tokens`, so such endpoints need to be switched to the new field by hand. Each of the other formats fixes its field name (Anthropic uses `max_tokens`, the Responses API `max_output_tokens`), so for a non-openai format the switch is greyed out and cleared on save. It also wires up a path never connected before: none of the five — planner / worker / chat / main agent / goal decomposition — had ever set an output cap, the openai family sent none and Anthropic fell back to the SDK's 8192, so just adding a config item without wiring this line meant even a filled-in number had no effect; now the value is resolved per round from the config like "streaming", taking effect on the next round after a failover switch. Behaviour is completely unchanged after an old-database upgrade (the new column defaults to 0 and an empty field name).
- Clicking "test" in the background now prints each HTTP attempt's status code and the gateway's raw response body into the server log (the body trimmed to 4K), to help diagnose a 401, a quota message, empty frames, an HTML page returned and so on, instead of only the ok / err the UI collapses it to. This log does not depend on the "LLM recording" switch.

#### Changed

- The task LLM config chain can now be edited in any state, no longer restricted to "running / paused / config chain exhausted": after a task ends (done / failed / timeout) the main agent conversation still uses this chain, and when a model on the chain had a problem it could previously be neither changed nor interacted with. Both the backend HTTP and the DB transaction terminal-state checks are removed, and the frontend dialogue opens editing and saving for terminal-state tasks too. Saving a terminal-state task no longer reopens quota-blocked intents (those intents would be moved to open with no worker to execute them and no longer meeting the "rerun intent" condition); to keep running, still use rerun intent / add a goal, which pull the task back into a running state.

### Agent

#### Changed

- "Message a running Worker to adjust its direction" is changed to reuse the existing pause / resume + transcript resume mechanism, behaving like the main agent conversation: it previously used a home-grown intervention-persistence protocol, touching the scheduling barrier, the recovery flow and a dozen activity-query filters. Now the message is injected on the next round's input, the intent runs directly in a dedicated goroutine, unconstrained by the 3-slot worker pool and running as soon as sent; the frontend keeps the message box and restores the "continue directly" button, with sending carried over SSE. No DB schema change. Trade-off: the message is kept only in memory with no crash recovery, and when sent the task may momentarily exceed its concurrency by one worker (a low-frequency scenario, acceptable).

### Tasks

#### Fixed

- Fixed an out-of-memory (OOM) crash when archiving a large task: archiving is changed to stream snapshots in, no longer reading the whole task into memory at once; it also closes three recovery gaps on the cold-archive path — on a modern install traffic is only in SQLite, and previously a crash between the PostgreSQL commit and the SQLite commit would leave an archived task's traffic stuck in hot storage with no way to recover, and now a staging log is written whether or not a historical directory exists, and a missing `journal.json` is also treated as discardable.
- Fixed system lag when there are many tasks: there was a noticeable delay loading conversations and loading the interface. The task list, task context and exploration record queries were all optimised, and the frontend's dashboard, conversation page and task detail page reduced duplicate requests at the same time.

### Assets

#### Changed

- Removed the company asset scope's "at most 256 rules" limit: a company entering its scope IP by IP / domain by domain easily hits this cap, after which it can only be split into multiple companies, while the scope itself is no slower for having more rules. The cap is removed in all three places — backend, frontend and demo mock — with a single rule still limited to 1024 characters, and the 2 MiB request-body cap kept as a fallback (about forty to fifty thousand rules).

### Skills

#### Fixed

- Fixed "upload failed: zip: unsupported compression" when uploading a skill package: Go's standard library only bundles the Store / Deflate decompressors, and a bzip2 or Zstandard package written by compression software at a non-default level cannot be unpacked. These two decompressors are now added (a pure-Go implementation, with no new external dependency); methods that genuinely cannot be unpacked such as Deflate64 / LZMA / XZ / PPMd, and encrypted packages, are now reported with a clear message before unpacking, naming exactly which file uses which compression method and how to repackage it, instead of throwing the underlying English error at the user.
- Fixed skill file-name validation judging a Chinese file name as illegal: path validation was previously an ASCII allowlist of `[A-Za-z0-9-_./]`, so a single Chinese-named file in the package (something like `参考/说明.md`) would fail the whole upload as "the package contains an illegal path". It is changed to a Unicode blocklist: file names in any language and spaces are allowed, while control characters, invalid UTF-8, zero-width and bidirectional control characters (RLO file-name spoofing), `\ % # ? * : " < > |`, and `..` / absolute paths / empty path segments are still rejected, with the directory-traversal defence unchanged. Skill names are similarly opened up — ASCII is still limited to lowercase letters, digits and hyphens (the agentskills.io spec), and non-ASCII letters such as Chinese can be used directly as a skill name, but spaces, dots and path separators are not accepted.
- Fixed garbled file names or a whole package being rejected after unpacking a Chinese package produced by Windows compression software: such a zip does not set the UTF-8 flag and writes file names in GBK, and they are now decoded with a GBK fallback before path validation. Also, a quoted frontmatter like `name: "中文技能"` now reads the skill name correctly.

### UI

#### Added

- The findings page gains an "all findings" flat view, set as the default, switchable with the original "grouped by task" view via a page-header tab: the grouped view has to be expanded task by task to see the vulnerabilities, a detour when you just want to scan the list across tasks. The flat view is one large cross-task table (10/20/50/100 per page), behaving exactly like the grouped view — tick to export, expand a row for the evidence and detailed report, rename / recategorise / change severity inline, change the triage status, deep-dive and delete. The two views share the stat cards and filter bar, switching does not lose the filter, and the current view and filters are recorded locally together; polling hits only the current view, and an inline change writes to both caches so switching does not show stale data.
- The findings page gains a "by asset" view: on the left an asset tree (company → root domain / IP → subdomain → service → endpoint, with the company level appearing only when an asset truly has an owner), on the right the findings under the whole subtree of the selected node, sharing the same table and the same filters as the other two views. The tree keeps only assets with findings, backfilling the ancestor chain on demand (even when a finding hangs only on the deepest endpoint, the levels above can still be reconstructed), and a node's count is aggregated over the subtree and de-duplicated by finding; a finding whose asset is deleted or that never had an associated asset goes into an "unassociated assets" bucket. Unlike the other two views, the asset view does not poll — it queries only when entering the view, changing a filter, adding/removing/editing a finding on the page, or clicking the tree's refresh button, since the left tree is a navigation structure with no need to recompute every 5 seconds. Each level of the tree shows only the increment relative to the level above (a subdomain with the root-domain suffix removed, a service shown as `https :443`, an endpoint showing only the path), with the full value in the hover hint and the breadcrumb; when there are too many nodes a whole level drops the endpoint/service tiers with a hint, and the counts still roll up.

#### Fixed

- Fixed the conversation records being squeezed and not fully visible in the mobile conversation detail: on a narrow screen the conversation list is collapsed to give the width to the records themselves.

### Dependencies

#### Changed

- Upgraded norma v0.3.2 → v0.3.3: adds `Config.MaxTokensField`, letting OpenAI Chat Completions' output cap be sent as `max_completion_tokens` instead (reasoning models accept only this key). The two keys are mutually exclusive and only one is sent, still defaulting to `max_tokens`.
- Upgraded `golang.org/x/mod` v0.37.0 → v0.40.0, fixing two dependency security warnings.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)
- [@begininvoke](https://github.com/begininvoke)

## [0.3.6] - 2026-08-27

### LLM

#### Fixed

- Fixed the "non-streaming" switch reverting to "streaming" after being saved and reopened (#69): the config list endpoint's DTO omitted the `streaming` field so the response never returned it, and the frontend, reading `undefined`, fell back to the default streaming; the actual write and DB storage were fine, it just could not be read back. The DTO restores the field (without `omitempty`, so `false` must also appear in the response).
- The connection test is changed to verify the model actually replies and to test using that config's real send/receive mode (#65): previously it only judged whether HTTP succeeded, and a request that went through with a zero reply (reasoning burning the budget / the body swallowed by a safety policy / a compatibility layer dropping `content`) also reported "connection successful", at odds with the "no reply" behaviour in a conversation; and the test always went streaming, so a non-streaming config actually tested another channel. Now an empty reply is judged a failure outright, a success shows the model's reply in the hint, and the current streaming switch is carried into the test, so "the test passes" is consistent with "the conversation works".

### Agent

#### Changed

- `list_facts` is changed to paging + keyword filtering, to avoid a single call bursting the context when there are many facts (#74): it returns the latest 20 by default, supporting `limit` (cap 100) / a `before` cursor / a `q` summary keyword, and returns `{facts, total, has_more, next_before}`; an overly long single summary is truncated by character count (the full text still goes through `node_detail`). The worker / planner prompts are updated to the paging semantics. The old database flushes the new parameter schema into the tool catalogue table via a one-off migration (`SeedTool` inserts on first only, otherwise the tool management page shows "no parameters").

### Tools

#### Added

- The "tool executions" page gains a tool-call count statistic (#72): a "stats" button on the toolbar opens a dialogue showing per-tool call count, proportion and failure count (sorted by count descending); it reuses the list's task / keyword filter, counts the whole result set rather than the current page, and fetches only when the dialogue is opened.

### Dependencies

#### Changed

- Upgraded norma v0.3.1 → v0.3.2: fixes reasoning/refusal silently dropped in OpenAI-family responses (Responses adds `reasoning_text`), de-duplicates the three names of the reasoning field, adds bounded retry for an empty response (zero content blocks), and fixes a gateway 400 from a compaction boundary cutting a tool pairing (also fixing the existing orphans already baked into the transcript).

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)

## [0.3.5] - 2026-08-25

### LLM

#### Added

- Each LLM profile supports a streaming/non-streaming toggle (streaming by default): on goes streaming SSE; off goes genuine non-streaming (`stream:false`, returning the complete JSON at once), which can work around some gateways' poor SSE implementations (empty frames, dropped reasoning-field frames), at the cost of losing in-run realtime progress and realtime token counting. The worker / planner / mainagent / chat / goals all take the value dynamically from the current active config; the three Provider wrapping layers — `llmpool` / `llmrec` / task runtime — are all non-streaming compatible; `llm_profiles` adds a `streaming` column with an `ALTER` for the old database (defaulting to `true`, so old configs are unaffected).
- Support for the OpenAI Responses API format in LLM configs: each config gains a third format, `openai-responses` (hitting `POST /v1/responses`), alongside Chat Completions / Anthropic; `BaseURL` is normalised with a default model of `gpt-5`; the `llm_profiles` `format` constraint adds `openai-responses` with an idempotent migration for the old database; and the frontend format dropdown adds "OpenAI (Responses API)". Depends on the norma v0.3.1 upgrade (including the `reasoning_content` round-trip fix).
- Recording the raw HTTP of LLM requests/responses: capturing the real wire body at the HTTP transport layer, keeping the tool schema, `tool_use` blocks and raw SSE frames the normalised view does not show; each attempt of norma's internal retries is kept in turn; `llm_records` adds `raw_request` / `raw_response` columns with an `ALTER` for the old database; and the recording page's detail panel adds a "raw" view toggle and request/response copy buttons (compatible with the `execCommand` fallback in an insecure context).

### Conversations

#### Changed

- The conversation list's multi-select is changed to a "multi-select" mode switch: the list no longer keeps a per-row checkbox by default (a cleaner look), and the header becomes a "N total + multi-select" button; clicking "multi-select" enters selection mode (checkboxes, select-all, bulk delete), "done" exits and clears the selection, and a bulk delete that fully succeeds exits automatically (if some fail it stays in selection mode for easy retry); a single rename / pin / delete still goes through each row's ⋯ menu.

### UI

#### Changed

- Enhanced the task management, conversation operation and traffic viewing experience (#57): the task list's column sort preference can be persisted and remembered, inline rename is triggered directly by an icon (no longer via a menu), and the drawer (sheet) interaction and traffic-viewing details were refined.

#### Fixed

- Worker asset labels show only the domain and IP, and handle the empty-label case correctly.

### Agent

#### Added

- The planner gains a "quantitative acceptance check" when judging a goal: when a goal contains a quantifiable acceptance condition (asset test coverage reaching X%, obtaining N flags, gaining a certain privilege), before `prove_goal` it must check the measured value in `graph_overview` (`coverage.pct`, the findings count etc.), and if the measured value is below target `prove_goal` is forbidden and it instead dispatches intents to make up the gap, and it must not mark met early on the grounds of "the main part is done/largely achieved". It fixes a goal requiring 100% coverage being judged complete while the measured value was only 40%.

#### Changed

- Rewrote the basis for "0 intents this round" in the planner prompt: the original text described 0 intents as "the most common, most important principle", which made the planner stop too early while the goal was unmet and there was still untested surface in scope. It now says 0 intents should be produced only in two specific cases — ① every direction thought of is already covered by an open/running/recent_done intent; ② the next step depends on the output of a currently running work and that output has not appeared yet (wait for it to finish and re-plan at the next wake after the graph updates). And it adds the reverse constraint: when there genuinely is a new direction uncovered and not dependent on a running work, or the goal is unmet with untested surface, do not stop because "0 intents is common".
- Strengthened the "evidence threshold for a negative conclusion" in the worker prompt: for a negative conclusion such as "not injectable/the port is closed/there is no login entry" that could make the planner abandon a whole direction, it requires exhausting the reasonable approaches within the intent (changing encoding/parameters/paths/methods) before concluding; if the approaches are not exhausted or the evidence is weak it is marked `confidence=inferred`, to avoid a careless `observed` negative welding a whole route shut (an incorrect negative early in a task especially skews the direction and is hard to self-heal).
- The above planner / worker default prompt changes are appended as a new version and switched to the current version via a one-off migration (`reseedPlannerPrompt` / `reseedWorkerPrompt`, each guarded by a settings flag); the old versions are kept in the version history, and a user who customised the prompt can restore it from the version record.

### Operations

#### Added

- New `reset-password.sh` to reset the admin (the username is fixed as `ARTEX`) password: it supports both local and docker deployments, with the connection info given explicitly or read automatically from `--dsn`/`$ARTEX_PG_DSN`/`config.json`; it generates a bcrypt hash compatible with the backend login using `pgcrypto` inside the database and writes it back to `settings.auth.password_hash`, with no service restart needed after the reset. The password is passed via an environment variable, never entering the process argv, and is escaped to prevent injection.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

## [0.3.4] - 2026-08-24

### UI

#### Added

- After ticking several tasks in the task list you can bulk-change their category, with the target category supporting "uncategorised" to move a task out of its current category; the whole batch is written in one transaction, and a failed item can only be a task deleted after being ticked.

#### Changed

- The new-task "task category" is changed from a dropdown to a searchable input box: typing filters the existing categories, a name not in the database is created and selected instantly on Enter (or by clicking "create" in the dropdown), and the selected item is shown as a removable tag; still limited to a single category.

### Conversations

#### Fixed

- Fixed sending a message being blocked by "LLM not configured, cannot converse" when the conversation has an LLM config selected but there is no global active config. The pre-send check originally looked only at the global active config, while the actual execution prefers the config the conversation selected, and the two resolution logics were inconsistent; they are now unified into one (the conversation/agent binding takes precedence, with the global as a fallback).
- The hint when conversation is impossible is now broken down by state: no config at all hints "add a config", a config present but not active hints "activate one or assign one to this conversation", and it no longer always shows "not configured", for easier diagnosis.

### Agent

#### Added

- For a task whose goals are all achieved, an intent the main agent issues via `add_intent` can be claimed and executed directly by a Worker and stops once done: the Planner no longer runs at this point (a task with no open goal does not enter planning), avoiding it re-judging the goals as achieved and cancelling the just-issued intent; once the frontier is drained the task returns to complete. Before issuing an intent the main agent asks the user, based on the intent's content, whether to register it as a formal goal, and registering it returns the task to regular autonomous planning.

#### Changed

- When `get_worker_trace` / `get_task_worker_trace`'s `step_ids` exceed the per-call cap (5), it no longer errors outright but returns the full content of the first 5 steps, and tells you via `returned_step_ids` / `omitted_step_ids` / `notice` in the result which were taken and which were not, with a hint that "there is no need to fetch more if these are enough". Duplicate and illegal ids passed in are de-duplicated and removed before counting.

#### Fixed

- The task list is changed to descending task id (newest-created first), replacing the previous sort by creation time. Multiple tasks created at the same moment have the same timestamp and sort unstably, and together with the 10-second polling and the random iteration of an in-memory map, they would swap places in the list frequently.

### Assets

#### Fixed

- Fixed company-attribution recomputation being broken by a single row of dirty data: when `assets.ip` stored a hostname (written by the agent or the asset API), `a.ip::inet` would throw `22P02`, making adding/editing a company asset scope and deleting a company all fail and roll back. It now uses the safe conversion `try_inet()`, skipping an illegal value rather than interrupting the whole statement.
- An unparseable `ip` is no longer silently skipped: after a company scope is saved it clearly reports how many assets have an `ip` that is not a valid IP (with the specific id and value), noting that these assets will not be attributed by IP/CIDR rules; the same information is written to the server log too, covering paths with no frontend response (deleting a company, scopesentry sync, agent writes).
- The task test scope's IP/CIDR matching likewise switches to `try_inet()`, replacing the previous regex guard that only checked the character set (a hostname of all-hex letters like `abc.def` previously still slipped through and triggered the same error).

#### Changed

- The `ip` field of `ip`, `service` and `endpoint` assets no longer accepts a hostname: `insert_assets` and the asset API return a per-item error with an `index` and give the fix directly (use `type=subdomain` and fill `domain`, or resolve the A/AAAA record first), so the agent can fix it itself and re-insert. Other assets in the same batch are unaffected and stored as normal.

### Contributors

- [@neouks](https://github.com/neouks)

## [0.3.3] - 2026-08-23

### Worker

#### Added

- A running Worker supports per-item pause, resume and cancel; a pause keeps the intent, facts and vulnerabilities, and a cancel transactionally cleans up the current intent and its direct output after execution exits.
- Added a `paused` intent state, an execution barrier and named termination reasons, to prevent late blackboard writes after a pause, cancel or task deletion.
- Added an optional task concurrency cap; creating, resuming, vulnerability deep-dive and queue backfill all go through a unified persistent FIFO admission path.

#### Changed

- A Worker's single-run wall-clock default duration is changed from 600 seconds to 1200 seconds; a timed-out task, once revived, re-times at its next real execution.
- The real execution states of the Worker, Planner and main agent uniformly drive the task state badge, fixing the problem of showing "idle" while a Worker is running.
- The Worker session keeps per-item control and the current session's token summary, with the model name moved to the right of the current session title.

#### Removed

- Removed the Worker multi-select, select-all and bulk pause/resume interface, and removed the Worker bulk-control API and the Mock contract with it.
- Removed the token badge and tooltip in the Worker list rows, while the underlying full token ledger and task aggregation endpoint are kept.

### LLM

#### Added

- Tasks support an ordered LLM config chain; when a provider's quota is clearly recognised as insufficient it automatically switches to the next config, persisting the current config, the exhausted state and an error summary.
- Running and paused tasks support editing the full config chain, reordering it and manually switching the current config, taking effect from the next LLM call.
- Automatic switch, manual switch and whole-chain exhaustion are written as structured system activity, with a de-duplicated reminder popped via the task activity stream.
- Added a task-role model resolution endpoint, uniformly resolving the config and model the Main Agent, Planner and Worker will use on their next call.
- Added an optional global LLM Pool, supporting a configured call order, per-model failure fallback, health status, cool-down recovery and a manual reset.
- Added an always-on LLM usage ledger, aggregating input, output and cache tokens by task, session, model and config.

#### Changed

- Goal decomposition, the Planner, the Worker and the main agent share the task-level LLM runtime (the resolution priority is below).
- Failover responds only to explicit quota, balance or billing errors; ordinary rate-limit, authentication, network, server and context errors do not switch by mistake.
- The LLM config page is changed to a list of config cards with a right-hand drawer for editing, and provides the Pool's rotation order, priority, exclusions, health status and recovery actions.
- The config-chain-exhausted message supports wrapping on a narrow screen; the current model is changed from an icon in the session list to a text label beside the current session title with a full tooltip.
- The order in which each in-task role resolves the LLM is adjusted to "agent binding → task config chain → global": a role explicitly bound to a model always runs on that model, only an unbound role falls to the task chain, and when the task chain is empty it falls to the global.
- An empty outbound proxy means a direct connection, no longer falling back to the `HTTP_PROXY`/`HTTPS_PROXY` environment variables (an explicit `ARTEX_LLM_PROXY` is unaffected); the proxy input supports `socks5://user:pass@host:port` with credentials.

#### Fixed

- A transient streaming failure before submission (before any output has been produced) is safely backed off and retried on the same provider, significantly reducing cases of "cut off after running just one or two tools, no summary, terminal state `model_error`"; quota exhaustion, an over-long context and deterministic 4xx errors are not retried and are still handled by failover and compaction recovery respectively.

#### Removed

- Removed the LLM icon-style marker in the session list, to avoid confusion with the Worker status icon.

### UI

#### Added

- Tasks support creating, renaming, deleting and filtering a global category; a new task can select a category directly.
- Added global task template CRUD and a right-hand management drawer; a new task can load a preset description and goals, or save the current content as a template.
- A new task supports linking multiple source tasks and multiple company asset scopes; the company scope automatically recognises domains, URLs, IPs, CIDRs, ICPs and company keywords from a single multi-line text box.
- Task test assets support real-time add and delete, recording the source as manual, company, inherited or agent-discovered; the Worker session title shows the current test assets and a source summary beside it.
- The findings page is grouped by task with independent in-group paging, and supports filling in a vulnerability description and creating a high-priority deep-dive intent.
- Conversations support rename, pin, unpin and delete; the task list supports bulk pause and resume of the current page.
- Traffic detail and tool-execution detail are changed to a right-hand drawer; the HTTP message completes the `Host` and highlights the request line, status code, headers, JSON and markup-language body.
- The task list action column gains "detail" and "pause/resume" buttons; the conversation send key can be configured in system settings (`Enter` / `Cmd+Enter` etc.), and the web-search area gains a proxy input box.
- The badge to the right of the session title is changed to show the LLM config name, with the model ID moved to a hover tooltip; a task can be given an optional name, and the task list gains a name column and search (falling back to the description when empty).
- The skills page gains usage count, last-used time and missing-dependency statistics, to help locate a skill that did not take effect or is not installed.

#### Changed

- The task title is changed to a focusable detail link; task assets, company assets, finding task groups and in-group vulnerabilities use real server-side paging, a stable sort and an exact total count.
- Adding a company switches to a right-hand drawer, with scope entry unified to multi-line text and offering real-time recognition, validation and a type preview.
- The main agent input box supports auto-growth, `Enter` to send, `Shift+Enter` for a newline, and avoids a mis-send during a Chinese input-method composition.
- The agent preview, task report and related detail uniformly use a shared Markdown renderer; the delete confirmation, long errors and the mobile drawer width are uniformly fixed.
- The task template selector displays and searches by template name and submits by template ID; the system's original font size is restored, and the app version is uniformly shown as `0.3.3`.
- The task total and the current session's tokens highlight only the input, cache-read and output values; the send button uses a cleaner up-arrow icon.
- The task overview's test scope shows the company name rather than the ID.

#### Fixed

- Ordinary text containing a dot is no longer mistaken for an ICP filing number.
- Fixed a clash in the variable catalogue with a global runtime variable (such as `{{.Now}}`), which made the agent editor's variable list render a duplicate key.

#### Removed

- Removed the task card's separate "enter" button, unifying entry to the detail on clicking the task title.
- Removed the dashboard's "new task" button, the Logo URL input when adding a company, and the vulnerability-count badge at the top of the findings page and in the task groups.
- Reverted the style that enlarged the global font by 10%, and removed the Worker selection box, the model icon and the row-level token statistics in the session list.

### Agent

#### Added

- A new task can link several existing tasks directly, inheriting, read-only in real time, the directly-source tasks' goals, facts, vulnerabilities, completed intents, asset scope and blackboard context.
- The blackboard read tools support querying a source task's nodes, facts, vulnerabilities and execution traces on demand; an inherited node carries a source marker and all write tools refuse to modify it.
- The company scope tools support domains, URLs, IPs, CIDRs, ICPs and company keywords; a keyword is only an agent scope hint and does not take part in automatic asset attribution.
- A vulnerability deep-dive operation creates, in the original task, a high-priority manual Worker intent with an asset anchor and a `derived_from` edge.
- The overview gains a "goal management" card, supporting manual view, add, edit and delete of goals; an add or edit notifies the Planner and revives the task, while a delete hard-deletes the goal node (cascading the edges and anchors) but does not revive.
- The main agent gains the `steer_work` tool by default, to inject a real-time correction into a running Worker without interrupting it or losing progress (still validating that the intent belongs to this task).

#### Changed

- A source task's intents do not enter the new task's frontier, and the new task keeps using an independent exploration, execution queue, working directory and conversation history.
- Deleting a running intent no longer destroys data: it instead stops to `stopped`, requires a deletion reason, hangs the reason as a fact on that intent and writes it into the payload, and the planner perceives it via the `cancelled` trigger (keeping the intent content and reason).
- The main agent conversation is changed to be driven by the server-side activity stream, with the input recoverable on a send failure; opening a conversation auto-sticks to the bottom and keeps the last reply visible after the detail lazy-loads.
- Pausing a task terminates the current Main Agent, Planner and Worker calls, but does not stop the user actively starting a new main-agent orchestration conversation during the pause.
- Cancel, close and a streaming interruption uniformly keep the real termination reason, the content already produced, the number of rounds run, the elapsed time, the tokens and the unreturned tool calls.

#### Removed

- Removed the main agent's client-side optimistic message echo, to avoid duplicate messages and cross-session streaming under a pause, a failure or concurrent activity.

### Constraints

#### Added

- The goal-decomposition stage first extracts operational constraints (allow/deny) before decomposing the goals, and the main agent can supplement them at runtime; constraints are injected into the Planner and Worker system prompts at the highest priority, and after de-biasing, diversity and surface-expanding exploration explicitly obey the constraints.
- The overview gains a "constraint management" card and add/edit/delete endpoints; the constraint injection scope can be toggled for the Planner / Worker separately (both on by default, read each round, taking effect immediately). The new table `task_constraints` uses `CREATE TABLE IF NOT EXISTS`, auto-created for the old database.

### Interception

#### Added

- Besides regex/string rules, command interception gains a model fallback approval: when not a single rule matches, the model makes an `ALLOW`/`ASK`/`DENY` semantic judgement, with the failure fallback action and the approval timeout action configurable; the interception page splits into two tabs, "interception rules / model config", and a model judgement result is tagged with a `[Model]` prefix and a reason.

#### Fixed

- Hardened the judge output parsing, to avoid a correct `DENY` judgement being mistaken for an allow.

### Traffic

#### Changed

- Traffic recording is changed to store the whole exchange in SQLite (a large body overflows to a hash-deduplicated blob bucket), with a trigram full-text index built on the text body, supporting any-substring and Chinese search; deletion degrades to a single SQL transaction, down from hours to milliseconds and no longer stalling recording during it. Added streaming download of a large body and a full-text parameter for `traffic_search`; the old file-tree data needs no migration and is still readable, searchable and deletable.

### Tasks and assets

#### Added

- Creating a task gains an "asset coverage feature" switch (on by default): when off, coverage is neither computed nor shown, the situation graph shows only assets, `task_scope` is not accumulated automatically, and the related tools are removed from the Planner / main agent; company association is unaffected by this switch.
- `insert_assets` gains a `related` marker per asset (default `true`): it only takes effect when coverage is on, and `false` only enters the shared asset store without counting towards this task's coverage (such as an incidentally discovered neighbouring site or an unrelated asset).
- The company scope and task test assets uniformly support text recognition of domains, URLs, IPs, CIDRs, ICPs and keywords; a domain/IP can create or reuse a global asset, while a CIDR/ICP/keyword is kept as task scope context.

### Build

- `build.sh --release` supports building Linux amd64/arm64, macOS amd64/arm64 and Windows amd64 in one go, and produces a zip release package with `skills/`, the config example and the README.
- Uses the Go linker to strip debug info and produce a zip release package; UPX is changed to an explicit option, to avoid its self-extracting ELF segfaulting at start-up in some Linux environments.
- The Release Workflow runs a start-up smoke test on the Linux amd64 binary and provides `SHA256SUMS` with the release package.

### Contributors

- [@neouks](https://github.com/neouks)

## [0.3.2] - 2026-08-20

### Added

- A new task supports linking multiple existing tasks, inheriting, read-only in real time, the directly-source tasks' facts, vulnerabilities, completed intents, asset scope and blackboard context; the new task still uses an independent execution queue, working directory and conversation history.
- Tasks support an ordered LLM config chain. When a provider's quota is clearly recognised as insufficient it automatically switches to the next config, persisting the current config, the exhausted state and the structured audit activity.
- Running and paused tasks support editing the LLM config chain, reordering it and manually switching the current config; automatic switch, manual switch and whole-chain exhaustion are hinted on the task detail page.
- A running Worker supports pause, resume and cancel. A pause keeps the blackboard data, and a cancel transactionally cleans up the intent and the facts, vulnerabilities and execution records it directly produced after the Worker stops writing.
- Deleting a task can optionally also clean up the associated assets, traffic, vulnerabilities and task landing files, and adds a deletion barrier, concurrency protection and an auditable deletion statistic.
- Added an optional task concurrency cap; a new task reaching the cap queues FIFO and starts automatically once a running slot is freed.
- Added task asset paging, company asset paging, task category statistics and a paged-intent Mock contract.
- Added the `build.sh` single-binary build script, supporting static frontend export, resource embedding, cross-platform targets and build-version injection.

### Changed

- A task-level explicit LLM config chain coexists with the existing global LLM Pool; an explicit chain continues to use strict quota-failover semantics, and with no explicit chain it follows the agent binding and global config rules.
- The main agent input box supports auto-growing multi-line input, `Enter` to send, `Shift+Enter` for a newline, and avoids a mis-send during a Chinese input-method composition.
- The Planner, Worker and main agent share the task-level LLM runtime; the task chain uses the smallest context window among the candidate models as the safe compaction threshold.
- The task detail page shows running, idle and paused states by the real LLM call status; the source task's facts, vulnerabilities, intents, asset references and graph nodes are uniformly marked with their source and kept read-only.
- The agent preview, task report and related detail views uniformly use a shared Markdown rendering component.
- The LLM model config uses a card and drawer interaction, with the model list supporting independent scrolling within the drawer.
- Pausing a task no longer blocks the main agent conversation: the main-agent orchestration conversation is independent of the task pause, and new messages can still be sent during the pause (the pause only terminates the round currently in progress).
- A Worker's single-run wall-clock default duration is changed from 600 seconds to 1200 seconds.

### Fixed

- Removed the main agent console's optimistic echo, switching to pure server-side data rendering, fixing messages getting jumbled or crossing into another conversation under a pause or send failure.
- Opening a main agent conversation scrolls to the bottom by default and shows the last reply in full: the last reply's full content auto-sticks to the bottom after lazy-loading, no longer being pushed off screen.
- Fixed the main agent conversation continuing to run after a task is paused, and the orchestration agent not stopping the main agent in step when it pauses a task.
- Fixed the task state badge and action button state being out of sync when a task completes or the Planner, Worker or main agent is actually running.
- Fixed late blackboard writes or leftover files possibly arising between a Worker cancel, a task deletion and concurrent writes.
- Fixed a broken Markdown preview, the delete-confirmation long text overflowing, the mobile width, and some task-detail buttons being misaligned.
- Added named termination reasons to all agent cancel paths, so activity detail can show the canceller, the terminal state, the number of rounds run, the elapsed time, the token usage and the unreturned tool calls.
- Fixed a race where the parent context could pre-empt and overwrite the named `shutdown` reason on backend shutdown, and garbling from a Chinese activity summary being truncated by bytes.
- Fixed a cancel event with partial streaming output losing the real termination reason, while keeping the content produced before the cancel.

### Contributors

- [@Autumn-27](https://github.com/Autumn-27)
- [@neouks](https://github.com/neouks)

[Unreleased]: https://github.com/Autumn-27/ARTEX/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/Autumn-27/ARTEX/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/Autumn-27/ARTEX/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/Autumn-27/ARTEX/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/Autumn-27/ARTEX/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/Autumn-27/ARTEX/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Autumn-27/ARTEX/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Autumn-27/ARTEX/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Autumn-27/ARTEX/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Autumn-27/ARTEX/compare/v0.3.1...v0.3.2
