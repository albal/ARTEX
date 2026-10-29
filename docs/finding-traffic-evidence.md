# Multiple traffic evidence for a finding

A finding detail's "linked traffic" supports multi-selection across pages, a purpose and note, ordering and unbinding. The traffic page can also multi-select records and link them to one existing finding at once. The evidence of a finding inherited by a task is read-only; to change it, go to the source task.

The "Agent automatic traffic binding" setting in system settings is off by default; the read and write endpoints are `agent_traffic_binding` on `/api/settings`. Enabling it increases the token consumption from viewing requests/responses, tool calls and prompts; the next round of the agent uses the new setting. When off, the automatic-binding parameters and the re-bind tool are hidden, no automatic-binding guidance is injected, and automatic bindings newly submitted by an already-running session are rejected. Manual binding, traffic capture, reading saved evidence and export are unaffected.

When on, the default flow is "finding stored → the reporter agent is triggered automatically → check and bind traffic → write the report against the latest evidence version". The reporter keeps the verification commands, key output, and the real traffic IDs already in hand and their purpose in `evidence`; the reporter agent, combining the finding detail and the execution record, verifies with `traffic_search` / `traffic_get` then calls `bind_finding_traffic`, then reads the latest `version` and saves the report. When the switch is off, the reporter agent does not additionally get the raw traffic search/read tools and does not bind automatically; it can still read manually-bound snapshots and generate a report.

Backwards-compatible with existing callers: `report_finding`'s `traffic_refs` / `evidence_hint_id` can still bind explicitly and immediately. Binding is optional: for non-HTTP vulnerabilities such as TCP, or when nothing was captured or no exact record is found, a report can still be filed and written with the references omitted; keep command output, logs and other verifiable evidence, ideally explaining why nothing was bound, and no new required field is added. Submitted IDs must all be valid with complete bodies. A failure of any one rolls back this binding operation; an explicit bind-with-report failure rolls back the whole report. Re-adding the same snapshot does not add a binding, nor overwrite the note.

## Agent numbering and report versions

`report_finding` gains optional parameters, and the array order is the initial evidence order:

```json
{
  "traffic_refs": [
    {"traffic_id": "a real traffic ID", "role": "baseline", "note": "a normal account request"},
    {"traffic_id": "another real traffic ID", "role": "proof", "note": "the reproduction request"}
  ]
}
```

The roles are `baseline` (a normal control), `proof` (proof of the vulnerability), `verification` (supplementary verification) and `supporting` (supporting evidence, the default). Verify the real records with `traffic_search` / `traffic_get` first; domain and time are only for candidate filtering and do not imply task attribution.

The prompts reference [CyberStrikeAI's vulnerability-reporting tool guidance](https://github.com/RuoJi6/CyberStrikeAI/blob/54d56774b8bd285817d16d48b70a4a5e6e0963f7/internal/app/vulnerability_tools.go), combined with this project's optional-binding convention, and introduce no required "reason for no packet" validation. Do not guess IDs, and do not re-probe just to collect packets.

The first line of the return is still `finding recorded: <exploration node ID>`; the JSON that follows provides the standalone finding record `finding_id`, the exploration node `finding_node_id` and a binding summary.

- `get_finding_traffic(finding_id)` uses the **standalone finding record ID**, and returns an ordered list and the `version`; passing `binding_id`, `side=request|response`, `offset` and `length` reads it in segments, at most 8192 bytes per segment.
- `update_finding_report`'s `finding_id` **continues to use the exploration node ID**. It gains `evidence_version` set to the version actually read; a change in evidence during generation rejects a write with the old version, so it must be re-read and regenerated.
- When an old report call does not pass a version, it does not claim to overwrite the existing traffic evidence. After a change in binding, note, purpose or order, an existing report is marked as needing an update.

With automatic binding on, `add_hint` / `add_task_hint` support saving `traffic_refs` in a single hint or in each element of a batch `hints`. A Planner reporting on someone's behalf can pass `evidence_hint_id` to explicitly pick the references in the matching hint of this task, and cannot reference an inherited hint. The system does not guess a binding by domain, time or browsing history. A failed submission does not produce a partial finding or trigger the report early.

For a finding that missed a binding, use `bind_finding_traffic(finding_id, traffic_refs)` to bind it later, with no need to re-register. `list_findings` / `list_task_findings` / `node_detail` / `get_task_node_detail` return an explicit `finding_id` and `finding_node_id`; the old `id` keeps the exploration node semantics.

At start-up only optional properties are added to the old tool schemas, the original default traffic tool bindings are extended to the reporter agent, and the re-bind tool is given to the reporter agent by default. Custom binding lists, prompts, descriptions and enabled state are kept. The guidance is added uniformly after the final tool assembly: the reporting role is responsible for handing over existing evidence, and the reporter agent is responsible for checking, binding and writing the report. When a platform conversation lacks task context, it should hand over to the task agent via a structured hint rather than reporting directly. Existing evidence should be handed over before judging a task complete; a no-packet case does not force a wait. A failed `report_finding` does not trigger the reporter agent.

## API

Base path: `/api/exploration/findings/{finding_id}/traffic`, using the standalone finding ID. It follows the existing authentication; `context_task` checks task visibility and inheritance read-only.

| method / relative path | request / return |
| --- | --- |
| `GET` | ordered summary, evidence version, report-adopted version |
| `POST` | `{"traffic_refs":[...]}` whole-batch append |
| `PATCH /{binding_id}` | `{"version":1,"role":"proof","note":"note"}` |
| `DELETE /{binding_id}` | `{"version":1}` |
| `PUT /order` | `{"version":1,"binding_ids":["2","1"]}`, must be the complete list |
| `GET /{binding_id}` | snapshot metadata and a bounded body preview |
| `GET /{binding_id}/body` | `side`, `offset`, `length`; `download=1` downloads the full raw bytes |

A version/order set conflict or a write while archiving returns `409`; an inherited write `403`; a binding that does not exist or does not belong to the finding `404`; traffic/attachment read and verification failures return explicit errors.

## Storage and migration

An idempotent migration on PostgreSQL at start-up: adds `traffic_evidence_snapshots`, `finding_traffic_bindings`, and `findings.evidence_version` / `report_evidence_version` (default 0). It does not guess a re-bind from historical text.

A snapshot saves the original traffic ID, capture time, URL, method, status, request/response headers, body length and SHA-256. The body is stored by hash at `<data>/evidence/blobs/<first two chars>/<hash>.bin`, separate from the cleanable `data/traffic`, and several findings can share a snapshot/body. A snapshot has no content-update endpoint, and read and export fail when verification mismatches.

The full body is read under the original traffic's write lock, including a large-body blob and old-directory records. The file is persisted and verified first, then a single PostgreSQL transaction writes the exploration node, intent relations, finding, snapshot and bindings; the planner is notified only after the commit. A failure may leave an unreferenced file, but produces no partial business record.

A PostgreSQL advisory lock `7337741004` coordinates the evidence files and SQL references; the task row lock forbids evidence modification once archiving is queued. Recovery holds the evidence lock throughout, from installing the body to committing the metadata. Deleting a finding cascade-removes its bindings.

The cleaner runs hourly and only reclaims content that is unreferenced and not part of an in-progress operation, with at least a 24-hour delay. Ordinary traffic cleanup does not touch the evidence directory. When backing up hot data, back up both PostgreSQL and `data/evidence`.

## Export and archive

Markdown contains the ordered evidence list and version; JSON contains the metadata; CSV adds the count and binding IDs. `md-zip` keeps the finding Markdown and also provides:

```text
evidence/<finding_id>/<binding_id>/
  manifest.json
  request.http
  response.http
  request.bin
  response.bin
```

The Markdown references the messages via relative links. Before the download is sent, the attachment copy, hash verification, compression, disk sync and a CRC read-check of every ZIP entry are completed; anything missing/corrupt fails the whole download. A full attachment keeps the raw binary bytes.

Archive v3 collects snapshots and bodies by the finding's bindings, not relying on the original traffic or domain. Hot data is cleaned only after the package is verified; shared evidence is kept. Recovery verifies and installs the bodies first, then transactionally restores the metadata and bindings, and supports retry on failure. v1/v2 remain restorable, and the missing new fields are explicitly backfilled to 0.

## Validation and boundaries

Set up an independent, freshly created PostgreSQL test database for each test package, specified via `ARTEX_PG_DSN`, to avoid leftover task/model fixtures triggering background runs. Run the full tests of the relevant packages and confirm there are no skips caused by missing config:

```sh
# Before running each package, set ARTEX_PG_DSN to its own independent test database; an explicit config failure must error.
go test ./<package> -count=1
go test -race -p 1 ./evidence ./db ./agent ./server -run 'TestEvidence|TestFindingTraffic|TestFindingEvidence|TestReportFindingAtomicContract|TestTaskArchive'
```

Frontend validation includes `npx tsc --noEmit`, a Biome check of the affected files, a Webpack build and the `NEXT_EXPORT=1` static export. Use a separate cache directory to avoid overwriting a running dev server.

Local end-to-end acceptance uses separate ports, controlled HTTP / domain HTTPS targets and a temporary data directory, covering both binding entry points, cross-page selection, ordering/notes, error hints, inherited read-only, download, and — after deleting the original traffic — export, archive, reclaiming the hot body, restoring and verifying the hash.

The first version uses a global evidence coordination lock; during a large bulk bind/export or a slow attachment download, other evidence operations may wait. Evidence cannot be fabricated when a recording or full body is missing. This feature does not change the capture switch, nor handle the certificate issue of accessing an IP directly over HTTPS.
