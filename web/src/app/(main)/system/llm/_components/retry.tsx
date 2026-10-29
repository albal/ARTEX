"use client";

// Shared pieces for LLM retry settings: the "count + interval" for each of the five retry layers.
//
// The five layers from inside out: connect (SDK) → empty response (SDK) → same-provider safe window → rotation circuit breaker → intent rerun.
// The first three follow the endpoint, so each model profile can override the global defaults; the last two are process-level and exist only once globally.
//
// Every input follows the same "blank = not configured" semantics, matching the backend's db.RetryRule:
//   count      blank/0 = use the built-in default | -1 = disable this layer | >0 = use this count
//   interval   blank/0 = use this layer's own exponential backoff | >0 = use this fixed interval in milliseconds

import * as React from "react";

import { Loader2Icon, SaveIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { LLMRetryOverride, LLMRetryPolicy, LLMRetryRule } from "@/lib/types";

export const ZERO_RULE: LLMRetryRule = { attempts: 0, interval_ms: 0 };
export const ZERO_OVERRIDE: LLMRetryOverride = {
  connect: ZERO_RULE,
  empty: ZERO_RULE,
  stream: ZERO_RULE,
};
const ZERO_POLICY: LLMRetryPolicy = {
  ...ZERO_OVERRIDE,
  breaker: ZERO_RULE,
  intent: ZERO_RULE,
};

type LayerMeta = {
  title: string;
  /** Where this retry layer happens and who performs it */
  where: string;
  /** Which errors reach this layer, down to the status code, so nobody has to guess */
  trigger: string;
  /** Errors that look similar but do NOT go through this layer, so nobody fills it in, sees no effect and assumes a bug */
  skips?: string;
  desc: string;
  attemptsLabel: string;
  /** Default when the count is blank, used for the placeholder */
  defAttempts: number;
  /** Default strategy when the interval is blank, used for the placeholder */
  defInterval: string;
  /** What entering -1 as the count means */
  offHint: string;
};

export const RETRY_LAYERS = {
  connect: {
    title: "Connection retry",
    where: "SDK · Before receiving 200",
    trigger:
      "Cannot connect or haven’t received 200: connection reset / read-write timeout / DNS failure and other network-level errors, as well as HTTP 408, 429, 500, 502, 503, 504.",
    skips: "Other status codes (400, 401, 403, 404, 413, 422, etc.) are deterministic rejections; retrying will also fail, propagate immediately.",
    desc: "Resend the same request unchanged. Once the stream starts (200 received), mid-stream disconnections are not handled here.",
    attemptsLabel: "Retry count",
    defAttempts: 3,
    defInterval: "0.5s→1s→2s Exponential (capped 8s)",
    offHint: "-1 = Never retry; fail fast.",
  },
  empty: {
    title: "Retry on empty response",
    where: "SDK · OpenAI-only format",
    trigger:
      "HTTP 200, finish_reason Normal stop, but the whole response has no content block; gateway empty frame, missing thinking field, or sampling hiccup cause this.",
    skips: "Responses cut off by max_tokens are ignored (increase the output limit to fix; retry will just hit the same limit).).",
    desc: "Resend the entire prompt, which is expensive for long contexts; keep the retry count low.",
    attemptsLabel: "Retry count",
    defAttempts: 2,
    defInterval: "0.5s→1s→2s Exponential (capped 8s)",
    offHint: "-1 = Return empty response as-is",
  },
  stream: {
    title: "Retry within the same provider’s safety window",
    where: "This project · Before any output is delivered",
    trigger:
      "Issues occurring after the stream is established (200 received): mid-stream disconnection, provider overload, 429/5xx errors inside the stream; no token delivered to the caller yet.",
    skips:
      "Quota exhausted (402/insufficient_quota → rotate config), context too long (413/context length → compress), deterministic rejections (400/401/403/404/422) are never retried.",
    desc: "Replay the same request on the same configuration. Since no output has been delivered, replay won’t duplicate model output or tool execution.",
    attemptsLabel: "Retry count",
    defAttempts: 2,
    defInterval: "0.5s→1s Exponential (capped 4s)",
    offHint: "-1 = When the stream breaks, hand the intent over to the outer layer for a full rerun.",
  },
  breaker: {
    title: "Polling circuit-break",
    where: "This project · Process-level, single global instance",
    trigger:
      "Instant failures (429, 5xx, network errors) trigger circuit-break once they accumulate to the threshold; deterministic failures like insufficient balance (402), invalid key (401/403), or missing model (404) break immediately without threshold.",
    skips: "A successful call resets the counter, so occasional glitches won’t gradually trigger circuit-break.",
    desc: "After circuit-break, enter cooldown; during cooldown polling skips this configuration. State is persisted; restart does not lose it.",
    attemptsLabel: "Circuit-break after several consecutive failures",
    defAttempts: 3,
    defInterval: "1min→5min→30min Gradient",
    offHint: "-1 = Instant failures never trigger circuit-break (deterministic failures still do)",
  },
  intent: {
    title: "Intent rerun",
    where: "This project · Process-level, single global instance",
    trigger:
      "Previous layers didn’t catch it: worker ends with 'model_error'; inner retries exhausted, or the stream broke after output started (rewind unsafe, must rerun whole request).).",
    skips: "Quota exhaustion is handled by config rotation, not rerun here; when a task is paused/terminated/completing, yield immediately without using backoff time.",
    desc: "Rerun the entire intent from the beginning. It’s the outermost layer; a single rerun multiplies the retry counts of inner layers.",
    attemptsLabel: "Rerun count",
    defAttempts: 2,
    defInterval: "Fixed 3s",
    offHint: "-1 = Do not rerun; the intent is considered resolved blocked",
  },
} satisfies Record<string, LayerMeta>;

type LayerKey = keyof typeof RETRY_LAYERS;

/** Milliseconds in plain words, only echoed beside the input so nobody has to count zeros. */
function humanMs(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${Number((ms / 1000).toFixed(2))}s`;
  return `${Number((ms / 60_000).toFixed(2))}min`;
}

/** Controlled numeric input: empty string ↔ 0; intermediate states ("-", "1e") stay local as typed without disturbing the parent. */
function NumField({
  id,
  value,
  onChange,
  placeholder,
  min,
}: {
  id: string;
  value: number;
  onChange: (n: number) => void;
  placeholder: string;
  min: number;
}) {
  const [text, setText] = React.useState(value === 0 ? "" : String(value));
  // Keep up when the parent swaps in a whole new set of values (policy loaded, profile switched); typing never reaches here,
  // because by then value already equals the parsed local text.
  React.useEffect(() => {
    const incoming = value === 0 ? "" : String(value);
    setText((cur) => (Number(cur || 0) === value ? cur : incoming));
  }, [value]);
  return (
    <Input
      id={id}
      type="number"
      min={min}
      className="w-28 shrink-0"
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        setText(e.target.value);
        const n = Number(e.target.value);
        onChange(e.target.value.trim() === "" || !Number.isFinite(n) ? 0 : Math.trunc(n));
      }}
    />
  );
}

/** The two knobs for one retry layer. idPrefix keeps the label's htmlFor unique when it appears more than once on a page. */
export function RetryRuleFields({
  layer,
  idPrefix,
  value,
  onChange,
  compact,
}: {
  layer: LayerKey;
  idPrefix: string;
  value: LLMRetryRule;
  onChange: (r: LLMRetryRule) => void;
  /** true = the compact version in the profile drawer: drops the expanded explanation, keeping only the "which errors reach this layer" line */
  compact?: boolean;
}) {
  const meta = RETRY_LAYERS[layer];
  const human = humanMs(value.interval_ms);
  return (
    <div className={compact ? "grid gap-2" : "grid gap-3 rounded-lg border p-3"}>
      <div className="grid gap-0.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Label className="text-sm">{meta.title}</Label>
          <span className="text-muted-foreground text-xs">{meta.where}</span>
        </div>
        {/* Which errors reach this layer, down to the status code: if the knobs seem to have no effect, the error most likely never reaches this layer. */}
        <p className="text-muted-foreground text-xs">
          <span className="font-medium text-foreground">Trigger</span>: {meta.trigger}
        </p>
        {!compact && meta.skips && (
          <p className="text-muted-foreground text-xs">
            <span className="font-medium text-foreground">Skip this layer</span>: {meta.skips}
          </p>
        )}
        {!compact && <p className="text-muted-foreground text-xs">{meta.desc}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-n`} className="text-muted-foreground text-xs">
            {meta.attemptsLabel}
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-n`}
            min={-1}
            value={value.attempts}
            placeholder={`Default ${meta.defAttempts}`}
            onChange={(n) => onChange({ ...value, attempts: n })}
          />
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-ms`} className="text-muted-foreground text-xs">
            Interval ms
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-ms`}
            min={0}
            value={value.interval_ms}
            placeholder="Default backoff"
            onChange={(n) => onChange({ ...value, interval_ms: n })}
          />
          <span className="text-muted-foreground text-xs">{human ? `Fixed ${human}` : meta.defInterval}</span>
        </div>
      </div>
      {!compact && <p className="text-muted-foreground text-xs">Leave blank = use default; {meta.offHint}.</p>}
    </div>
  );
}

/** The three overridable layers in the model profile drawer (the three that follow the endpoint). */
export function ProfileRetryFields({
  value,
  onChange,
}: {
  value: LLMRetryOverride;
  onChange: (o: LLMRetryOverride) => void;
}) {
  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="grid gap-0.5">
        <Label className="text-sm">Retry override</Label>
        <p className="text-muted-foreground text-xs">
          Applies only to this configuration, overriding the global default in “Retry and Backoff”. Leave a field blank to follow global; set attempts to -1 to disable this retry layer.
          If interval is set, use fixed interval instead of exponential backoff. Circuit breaker and intent retry are process-level, adjustable only on the global page.
        </p>
      </div>
      {(["connect", "empty", "stream"] as const).map((k) => (
        <div key={k} className="border-t pt-3 first:border-t-0 first:pt-0">
          <RetryRuleFields
            compact
            layer={k}
            idPrefix="pf"
            value={value[k]}
            onChange={(r) => onChange({ ...value, [k]: r })}
          />
        </div>
      ))}
    </div>
  );
}

/** "Retry and backoff" tab: the global defaults for all five layers. */
export function RetryPolicyPanel() {
  const [policy, setPolicy] = React.useState<LLMRetryPolicy>(ZERO_POLICY);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const p = await api.llmRetryPolicy();
      setPolicy({ ...ZERO_POLICY, ...p });
    } catch (e) {
      toast.error(`Failed to read retry policy: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    if (saving) return;
    setSaving(true);
    try {
      // The backend clamps out-of-range values back into range and returns them; refresh from the returned values so what you see is what was saved.
      const saved = await api.saveLLMRetryPolicy(policy);
      setPolicy({ ...ZERO_POLICY, ...saved });
      toast.success("Saved, takes effect immediately (current in-progress call still uses old parameters)");
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  const set = (k: LayerKey) => (r: LLMRetryRule) => setPolicy((p) => ({ ...p, [k]: r }));

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-dashed p-10 text-muted-foreground text-sm">
        <Loader2Icon className="size-4 animate-spin" /> Read retry policy…
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      <div className="rounded-lg border bg-muted/30 p-3 text-muted-foreground text-xs leading-relaxed">
        A model call failure goes through five retry layers sequentially, from inner to outer:
        <span className="text-foreground"> Establish connection → Empty response → Same provider security window → Polling circuit-break → Intent rerun</span>
        . Outer layer is reached only after inner layer exhausts, so count is
        <span className="text-foreground">Multiplicative</span>
        ; max out each layer; a single jitter can consume dozens of requests.
        Leave all fields empty to use current defaults, matching behavior when this page is absent. The first three layers can be overridden individually in each model config.
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(Object.keys(RETRY_LAYERS) as LayerKey[]).map((k) => (
          <RetryRuleFields key={k} layer={k} idPrefix="gl" value={policy[k]} onChange={set(k)} />
        ))}
      </div>

      <div className="flex gap-2">
        <Button onClick={save} disabled={saving}>
          {saving ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
          Save
        </Button>
        <Button variant="outline" onClick={() => setPolicy(ZERO_POLICY)} disabled={saving}>
          Restore all defaults
        </Button>
      </div>
    </div>
  );
}
