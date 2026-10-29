# Side-question long conversations and the context budget

Fixed on 2026-09-11. The original implementation treated the request JSON's character count directly as tokens and inherited the main task's 32K output reservation, so with a lot of HTML, JS and tool results it rejected ordinary side questions prematurely.

## Open-source implementation review

- [Grok CLI side-question context](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/agent.ts#L739): takes fragments from the most recent user and assistant text, a character budget of about 2000, at most 400 characters per entry. It keeps no continuous side-question history on this path.
- [Grok CLI independent request](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/utils/side-question.ts): an independent cancellation signal; a 2048-token output cap where the model supports it; no tools.
- [Grok CLI main-session compaction](https://github.com/superagent-ai/grok-cli/blob/fb97af83f06dca873281d60168430f06c8de6324/src/agent/compaction.ts): estimates tokens, keeps recent content, updates new content into the old summary, and handles cross-turn truncation.
- [OpenCode session compaction](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/compaction.ts): full-request estimation, output/buffer reservation, recent content plus a rolling summary, a tool-less summary request; that implementation defaults to a recent budget of 8000 and a 4096-token summary output cap.
- [OpenCode overflow recovery](https://github.com/anomalyco/opencode/blob/b3f1a96c6dd7adeb28b36dd11add1998fc84d67b/packages/core/src/session/runner/llm.ts): overflow recovery is only attempted before assistant output has begun, and the call after recovery does not enter the same overflow-recovery path again.

ARTEX borrows the independent output budget, the recent-content-plus-rolling-summary approach, and limited recovery. It keeps norma v0.3.6's structured messages and tool pairing, does not copy Grok's text excerpting, and does not write OpenCode's main-session compaction events into the ARTEX main transcript.

## Request budget and execution

- Messages follow norma's per-content-block UTF-8 byte estimate with a 4/3 margin; the system prompt, tool schema and message wrapping overhead are also counted. The estimate is not the model's exact token count.
- The side-question output is at most 8192 tokens by default, and never exceeds the output cap already set in the main config. The service environment variable `ARTEX_BTW_MAX_OUTPUT_TOKENS` can set a cap of 256–32768; it does not change the product's default model or the main task's parameters.
- The input budget is the context window minus the output cap and a safety margin; an unknown window uses the platform default of 200K. The safety margin is 5% of the window, with a minimum of 128 and a maximum of 8192 tokens.
- Successful Q&As are loaded at most 20 per batch by increasing sequence number. The raw text of at most 20 is kept, with a token budget of at most 1/4 of the input budget and no more than 16K.
- Over-budget Q&As are updated into the rolling summary. The summary carries the historical source and context time; a historical assistant answer is not the same as new tool evidence, and on conflict the latest main snapshot takes precedence.
- When the main context is still too long, only the older messages in the copy are summarised, keeping at most 8K tokens of recent content; the cut point does not split a tool call from its result. An over-large single group goes into the summary whole.
- The summary input is UTF-8-safely chunked to the actual remaining window, with a 2048-token output cap; an empty summary, truncation, a tool call or exceeding the summary budget none of these are cached. One side question makes at most 12 summary calls, subject to the same 120-second timeout; reaching the cap fails explicitly rather than looping forever.
- If the model first returns a context overflow before any text or tool call has been output, it shrinks further and retries at most once; if the estimated size does not drop, recovery stops immediately. Other model errors and partial streaming output do not trigger this recovery.
- All usage obtained — including from the summary, failed attempts and on cancellation — is accumulated onto the same side-question request. When the Provider returns no usage it can still only record zero, not pass off an estimate as actual usage.

## Persistence and interface

`side_question_sessions.memory` saves the summary of older Q&As, the ordinals it covers, and the main context summary cached by snapshot identity. `side_question_requests.context_info` saves the preparation stage, the actual number of replayed groups, the summary usage and the budget estimate.

A summary is saved only while the original request is still running and the clear version matches; a clear also clears the cache, and a late write does not restore cleared data. A new snapshot does not reuse an old snapshot's summary. The summary fields are saved with a v3 task archive; on restoring an old v3 the missing fields are backfilled with an empty object, and v1/v2 remain compatible.

A POST accepts and returns the request first, with preparation and compaction running in the background, holding neither the admission lock nor a database transaction. The SSE/history shows the preparation, Q&A consolidation, copy compaction and answer stages; a compaction failure is saved as the terminal failure state of that side-question request. The frontend keeps the error and restores the draft of the failed question, without a floating notification obscuring the input box; the history poll no longer clears a submission error.

## Validation record

- 19/20/21/50-group replay, retention of older conclusions across 20 groups, summary-cache reuse across a restart: automated, passed.
- An over-long multi-byte answer and code context, chunked request budget, tool pairing, snapshot immutability, new-snapshot cache invalidation: automated, passed.
- Summary failure/cancel/truncation/over-length/tool return, clear races, the call cap, only-once overflow recovery, and no retry on a partial stream: automated, passed.
- Paging, restart, v1/v2/v3 archive, summary-cache-and-budget-metadata archive restore, an old v3 missing new fields, and 20 parent sessions sharing four concurrency slots on an independent PostgreSQL: passed.
- The candidate service's Go build, the frontend TypeScript check, a Biome check of the changed components, and a Next.js production build in a separate directory: passed.
- The built-in browser, with a separate UI fixture, verified at 1280×720 and 390×844 the consolidation stage, the summary-scope hint, draft restore after a failure, no floating error notification, no horizontal overflow and no console errors. The temporary fixture has been removed.
- A read-only replay of an existing local Worker snapshot passed the new budget check; e.g. Worker #3's 293085-character snapshot is no longer rejected by a mistaken local character count. This item made no external model call.
- The real-conversation test of sending a private Worker snapshot to Grok was refused by the automated-approval review and not executed, and is not counted as passed.
- At 2026-09-11 00:37 the local backend was restarted at the user's request, keeping the original database, data directory and login config. The running file and the candidate binary have the same SHA-256; `/api/health` through both the backend and the frontend proxy returned healthy.

Validation commands (using independent test databases only):

```sh
go test -race ./sidequestion ./db ./server -run 'TestSide|TestCheckpoint|TestSnapshot|TestBuildRequest|TestService|TestMainSide|TestTaskArchive' -count=1
go build ./cmd/artex
npx tsc --noEmit
npm run build -- --webpack
```

The frontend production build uses a separate copy, to avoid overwriting the currently previewed `.next`. The candidate service is at `/private/tmp/artex-btw-budget-candidate`, copied to `/private/tmp/artex-btw-preview/artex` and started; the original binary is backed up as `artex.before-context-budget` in the same directory.
