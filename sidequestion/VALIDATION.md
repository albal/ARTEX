# `/btw` validation record

Date: 2026-09-10. Branch: `codex/btw-side-question`. Baseline: `8dae851b9b622f2ff2631f332fde9719d0b16fba`.

Independent PostgreSQL test databases and a data directory were used; real model credentials were injected only into the isolated test environment, not written into the code or this record, and the product's default model was not changed. Go 1.26.3, norma v0.3.6, Next.js 16.2.9.

The real model conversations, return objects, engineering assertions and the raw Qwen review text are saved in [validation-2026-09-10.json](validation-2026-09-10.json), which contains no API credentials.

## Engineering checks

| scope | result | evidence |
| --- | --- | --- |
| deep copy of structured messages and tool parameters | passed | `TestCheckpointDeepCopyAndBoundaries` |
| summary / compaction requests do not overwrite, a complete reply and terminal state publish, a half-reply is excluded | passed | `TestCheckpointDeepCopyAndBoundaries`, `TestSnapshotExcludesPartialStreamAndSelectsPoolMember` |
| the actual model pool member identity | passed | `TestSnapshotExcludesPartialStreamAndSelectsPoolMember` |
| tool pairing, 20-group replay, budget trimming and the overflow error | passed | `TestBuildRequestCompactionToolPairingAndBudget` |
| main/side in parallel, two-way cancellation isolation | passed | a blocking Provider, `TestMainSideConcurrencyAndIndependentCancellation` |
| no tool execution, streaming / non-streaming, usage already obtained on failure | passed | `TestServiceNoToolsAndUsageOnFailure` |
| a real norma ChatAgent + local Read tool, main transcript / activity isolation | passed | `TestSideActualChatCheckpointToolResultAndTranscriptIsolation`, streaming and non-streaming sub-cases |
| persistence, paging, idempotency, partial-answer retention across a restart | passed | `TestSideHistoryIdempotencyPagingAndRecovery` |
| a clear vs late-write race, parent-resource deletion, version comparison | passed | `TestSideClearLateWritersAndDeletedParent` |
| MainAgent / Worker archive and restore, v1/v2/v3 | passed | `TestSideTaskArchiveVersions` |
| the three parent interfaces, authentication, resource ownership, Worker logical deletion | passed | `TestSideHTTPGlobalLimitTaskWorkerAndDeletion`, `TestSideCheckpointPersistsBeforeAdmissionAndRestart` |
| a busy main session can still take a side question, independent SSE reconnect / disconnect, cancel, clear | passed | `TestSideHTTPBusyIsolationClearAndReconnect` |
| 1 per parent session / 4 global concurrency | passed | two `TestSideHTTP…` cases |
| snapshot stored before submission, resuming a question after a restart, an old session cannot fabricate a snapshot | passed | `TestSideCheckpointPersistsBeforeAdmissionAndRestart` |
| refuse to continue after the cached config is deleted or the model changes | passed | `TestSideRejectsDeletedOrChangedCachedProfile` |
| cancel before archiving and wait for the final answer and usage to be stored | passed | `TestSideTaskDrainPersistsBeforeArchive` |
| usage recorded only once and attributed to the side question when the streaming consumer cancels early | passed | `TestSideUsageRecordedOnceOnConsumerCancellation` |
| a Worker / deadline runtime context auto-restored after a restart keeps publishing new snapshots | passed | `TestSideRestoredWorkerRuntimePublishesNewCheckpoint` |
| race check of the relevant packages | passed | the command below |
| TypeScript and the production build | passed | `npx tsc --noEmit`, `npm run build` |
| Biome of the new frontend modules | passed | `biome check`, 3 new modules |

With `ARTEX_PG_DSN` set to a separate disposable database, the automated checks can be reproduced (do not point it at a production database):

```sh
go test -race ./agent ./db ./server ./sidequestion ./llmrec ./llmpool \
  -run 'Test(Side|Checkpoint|Snapshot|BuildRequest|Service|MainSide|CaptureRun|TaskArchive|CompleteForwards|StopIntent|CancelIntent)' -count=1
cd web
npx tsc --noEmit
npx biome check src/lib/side-questions.ts src/hooks/use-side-questions.ts src/components/side-question-workspace.tsx
npm run build
```

The full Go regression is not all green: the `server` package has two existing tests that fail during temp-directory cleanup, both reporting `TempDir RemoveAll … directory not empty`:

- `TestInheritedActivityDetailAndRelationDeletion`
- `TestTaskMetadataPatchReturnsRenameAndPin`

After exporting the source from the unmodified baseline above and rerunning the `server` package in the same isolated environment, these two cleanup failures reproduce too. The baseline run additionally showed a target-node-count assertion failure in `TestCoreTaskLifecyclePG`; the final modified `server` regression has no such assertion failure. The other packages pass, and this change's side-question cases and race check pass. Baseline issues are not marked as passing this acceptance, nor were existing assertions changed to hide problems.

The Next.js build outputs the existing multi-lockfile / workspace-root inference warning; the build completed and all pages generated successfully.

## Browser checks

Using the Codex In-app Browser, connected to a separate local Go service and the Next.js dev server. The following manual-automated operations were done on desktop and a 390 × 844 narrow screen, checking the screenshots and browser logs:

- Typing `/btw` during an ordinary chat run shows the main content and the side question at the same time; the desktop side panel works.
- Consecutive follow-ups; stopping the side question keeps the part already generated; the main flow continues.
- Closing the panel keeps the request going, and reopening restores the completed answer; after a page refresh an empty `/btw` restores the history.
- The narrow-screen Drawer's input, buttons, history and close all work, with no horizontal overflow.
- Clear uses a confirmation dialogue; after clearing the history is gone while the main transcript and snapshot are kept.
- Asking in a task's MainAgent and two Workers separately and switching between them: the agent labels and history do not cross over.
- A blocking local model fixture keeps a Worker running; submitting `/btw` from the Worker's main input box, after stopping the side question the Worker still shows a live run and its own pause button, and the side question saves a partial answer.
- The browser error / warning log is empty.

The controlled fixture is used to verify concurrency timing precisely, not relying on a real model's output speed. During debugging, two Worker-run checks did not form a valid concurrency window (the task had ended / the answer finished early); after fixing the fixture they were redone and passed; those initial operations are not counted as valid passes.

## Real model conversations

`grok-4.6` was probed first, via the OpenAI-compatible endpoint `http://127.0.0.1:12580/tingly/openai`. The probe returned HTTP 200 with the model name `grok-4.6` and `READY`, in 2.82 seconds. The first choice was available, so the Tingly `glm` or Zhipu `glm-5.3` fallback chain was not enabled; those two fallback services were not validated this time.

| scenario | actual result |
| --- | --- |
| asking about assets, goals and a marker during a main-session run | returned `redhaze.top`, read the homepage and summarised the goal, and `BTW-REAL-0910`; the side question completed in 16.97 seconds |
| asking the tool basis after the main session finished reading the homepage | correctly cited the WebFetch 200, the curl redirect 301 → 302 → 200, and the page title; 7.24 seconds |
| the side question asking Bash to create a test file | refused to execute, and the target file was not created; 7.74 seconds |
| a post-completion side question does not change the main context | the main transcript SHA-256 and the main activity records stayed consistent; the side question's tool execution count was 0 |
| a follow-up after genuinely stopping / restarting the Go service | kept the previous 3 side-question history entries, answering assets, markers and the title directly from the persisted snapshot, without rerunning the main agent |
| a new session using the Grok non-streaming config | correctly answered assets and `ATOMIC-0910`; returned and saved usage: input 11734, output 138, cache_read 11520 |

The asset case's main session used WebFetch and Bash/curl to read a public homepage, with a landing page of `https://id.redhaze.top/home` and a title of "RedHaze Group · global conglomerate portal". Bash staged the response in a local test file; no write was executed to a remote. This fact is verified separately from "the side question executed no tool".

Main transcript checksum: `e7e61f135a4a120954b539f357e8c4205d7d5cd7460dcaf3dc0fd066463e1d00`.

**Usage limitation:** Tingly's Grok streaming response returned no usage. A separate direct send with `stream_options.include_usage=true` verified HTTP 200, 12 data frames and 0 usage frames. So the 0 in the streaming tests means the endpoint provided no usage, and must not be read as no billing. The non-streaming usage and the fixture's failure / cancellation usage were all saved correctly.

## Qwen review

The review model `qwen-flash`, via the OpenAI-compatible endpoint `https://dashscope.aliyuncs.com/compatible-mode/v1`, HTTP 200. It was given the first three real side-question conversations, the main session's tool basis and the engineering assertions; it returned `verdict: accept`, `concerns: []`, judging the answers consistent with the asset, marker and page-reading evidence, and the side question's tool refusal in line with the constraints. Review usage: prompt 6625, completion 312, total 6937.

This Qwen review did not cover the service restart and non-streaming tests added later. Qwen's summary of "no write" was too broad: the main session's curl did create a local response temp file, as recorded explicitly above. Concurrency, zero tool execution and transcript isolation are judged by the engineering assertions; the model review only assists in assessing answer quality.
