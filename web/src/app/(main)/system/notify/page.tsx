"use client";

import * as React from "react";

import { BellIcon, PlusIcon, SendIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { NotificationChannel, NotificationFilter, NotificationMeta } from "@/lib/types";

import {
  CHANNEL_FIELDS,
  type ChannelForm,
  emptyForm,
  KIND_LABEL,
  parseIDs,
  parseKeywords,
  parseKV,
  SEVERITY_OPTIONS,
} from "./_components/channel-fields";
import { ConfigField, FilterSummary } from "./_components/channel-form";
import { DeliveryList } from "./_components/delivery-list";
import { formatBacklog, StatTile } from "./_components/stat-tile";

// This page only orchestrates: loading data, maintaining form state and calling the API.
// Field definitions and parsing live in _components/channel-fields.ts, controls and the filter summary in
// _components/channel-form.tsx, and delivery records in _components/delivery-list.tsx;
// they were split out because each can be understood on its own, and crammed into one file this page was close to 1,100 lines.
export default function NotifyPage() {
  const [meta, setMeta] = React.useState<NotificationMeta | null>(null);
  const [channels, setChannels] = React.useState<NotificationChannel[]>([]);
  const [tab, setTab] = React.useState<"channels" | "deliveries">("channels");

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<NotificationChannel | null>(null);
  const [form, setForm] = React.useState<ChannelForm>(emptyForm("dingtalk"));
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  const [globalSaving, setGlobalSaving] = React.useState(false);
  const [baseURL, setBaseURL] = React.useState("");
  const [digestMin, setDigestMin] = React.useState("");

  const load = React.useCallback(() => {
    api
      .notifyMeta()
      .then((m) => {
        setMeta(m);
        setBaseURL(m.public_base_url);
        setDigestMin(m.digest_interval_min);
      })
      .catch((e) => toast.error("Failed to read push configuration: " + (e as Error).message));
    // A failure to load the channel list must be reported: failing silently would show as "no channels at all",
    // and users would think their configuration had been lost, which is more alarming than an outright error.
    api
      .notifyChannels()
      .then(setChannels)
      .catch((e) => toast.error("Failed to read channel list: " + (e as Error).message));
  }, []);
  React.useEffect(() => {
    load();
  }, [load]);

  function setF(patch: Partial<ChannelForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }
  function setCfg(key: string, value: unknown) {
    setForm((f) => ({ ...f, config: { ...f.config, [key]: value } }));
  }

  function openAdd() {
    setEditing(null);
    setForm(emptyForm(meta?.kinds[0]?.kind ?? "dingtalk"));
    setOpen(true);
  }

  function openEdit(ch: NotificationChannel) {
    setEditing(ch);
    // filter is a Go struct on the backend and always serialises to an object (never null), so no fallback is needed.
    const f = ch.filter;
    setForm({
      name: ch.name,
      kind: ch.kind,
      mode: ch.mode,
      enabled: ch.enabled,
      ratePerMin: String(ch.rate_per_min),
      // Credentials in the config echoed by the backend are mask values; they go into the form as is and are sent back unchanged on submit,
      // which tells the backend to keep the original values in the database.
      config: { ...ch.config },
      minSeverity: f.min_severity ?? "",
      includeText: (f.vulnclass_include ?? []).join("\n"),
      excludeText: (f.vulnclass_exclude ?? []).join("\n"),
      taskIDsText: (f.task_ids ?? []).join(","),
      assetIDsText: (f.asset_ids ?? []).join(","),
      onStatusChange: f.on_status_change ?? false,
    });
    setOpen(true);
  }

  // buildConfig turns the form state into a channel config.
  //
  // There is a single rule, with two kinds of value:
  //   - mask values ("__masked__...") are sent back unchanged → the backend reads this as "this field was not changed; keep the stored value"
  //   - everything else is submitted as the user entered it, and an empty string means "clear this field"
  //
  // Credential fields get no special treatment (such as "skip if left blank"), because that would leave users **unable to clear**
  // a wrongly set key: there would be no action in the interface that says "I want to delete it". Under the current rule,
  // clearing the input box clears the field, so the meaning is unambiguous and under the user's control.
  // Mask values never appear in the input box (see ConfigField), so "there is text in the box" always means
  // "the user typed it".
  function buildConfig(): Record<string, unknown> {
    const defs = CHANNEL_FIELDS[form.kind] ?? [];
    const out: Record<string, unknown> = {};
    for (const d of defs) {
      const raw = form.config[d.key];
      if (d.kind === "switch") {
        out[d.key] = raw === true;
        continue;
      }
      if (typeof raw === "string" && raw.startsWith("__masked__")) {
        out[d.key] = raw;
        continue;
      }
      if (d.kind === "number") {
        const n = Number(raw);
        out[d.key] = Number.isFinite(n) && n > 0 ? n : 0;
        continue;
      }
      if (d.kind === "kv") {
        out[d.key] = parseKV(String(raw ?? ""));
        continue;
      }
      if (d.kind === "list") {
        out[d.key] = String(raw ?? "")
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean);
        continue;
      }
      out[d.key] = String(raw ?? "").trim();
    }
    return out;
  }

  function buildFilter(): NotificationFilter {
    return {
      min_severity: form.minSeverity || undefined,
      vulnclass_include: parseKeywords(form.includeText),
      vulnclass_exclude: parseKeywords(form.excludeText),
      task_ids: parseIDs(form.taskIDsText),
      asset_ids: parseIDs(form.assetIDsText),
      on_status_change: form.onStatusChange,
    };
  }

  async function saveForm() {
    if (!form.name.trim()) {
      toast.error("Please enter channel name");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        kind: form.kind,
        mode: form.mode,
        enabled: form.enabled,
        config: buildConfig(),
        filter: buildFilter(),
        rate_per_min: form.ratePerMin.trim() === "" ? undefined : Number(form.ratePerMin),
      };
      if (editing) {
        await api.notifyUpdateChannel(editing.id, payload);
        toast.success("Saved");
        setOpen(false);
      } else {
        await api.notifyCreateChannel(payload);
        toast.success("Channel added");
        setOpen(false);
      }
      load();
    } catch (e) {
      toast.error("Save failed: " + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function testChannel() {
    if (!editing) return;
    setTesting(true);
    try {
      const r = await api.notifyTestChannel(editing.id);
      toast.success(`Test message sent (${r.latency_ms} ms), please confirm in the group`);
    } catch (e) {
      // The backend passes back the channel's raw error faithfully; it is the only clue for diagnosing the configuration, so show it as is.
      toast.error("Test failed: " + (e as Error).message, { duration: 12000 });
    } finally {
      setTesting(false);
    }
  }

  async function removeChannel(ch: NotificationChannel) {
    try {
      await api.notifyDeleteChannel(ch.id);
      toast.success(`Deleted: ${ch.name}`);
      setOpen(false);
      load();
    } catch (e) {
      toast.error("Delete failed: " + (e as Error).message);
    }
  }

  async function toggleEnabled(ch: NotificationChannel) {
    try {
      await api.notifyUpdateChannel(ch.id, { enabled: !ch.enabled });
      load();
    } catch (e) {
      toast.error("Operation failed: " + (e as Error).message);
    }
  }

  async function toggleGlobal(on: boolean) {
    setGlobalSaving(true);
    try {
      await api.setSettings({ notify_enabled: on });
      setMeta((m) => (m ? { ...m, enabled: on } : m));
      toast.success(on ? "Push enabled" : "Push paused");
    } catch (e) {
      toast.error("Operation failed: " + (e as Error).message);
    } finally {
      setGlobalSaving(false);
    }
  }

  async function saveGlobal() {
    setGlobalSaving(true);
    try {
      const patch: Record<string, unknown> = { notify_public_base_url: baseURL.trim() };
      const n = Number(digestMin);
      if (Number.isFinite(n) && n > 0) patch.notify_digest_interval_min = n;
      await api.setSettings(patch);
      toast.success("Saved");
      load();
    } catch (e) {
      toast.error("Save failed: " + (e as Error).message);
    } finally {
      setGlobalSaving(false);
    }
  }

  const fields = CHANNEL_FIELDS[form.kind] ?? [];
  const secretKeys = new Set(meta?.kinds.find((k) => k.kind === form.kind)?.secret_keys ?? []);
  const defaultRate = meta?.kinds.find((k) => k.kind === form.kind)?.default_rate_per_min ?? 0;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Notification push</h1>
          <p className="text-muted-foreground text-sm">
            Push to DingTalk / Feishu / WeChat Work and other channels when a vulnerability is discovered · Each channel can independently set push timing and filtering rules
          </p>
        </div>
        {meta && (
          // A div rather than a label: Switch has its own aria-label, and wrapping it in a label
          // would associate with no native control while making a click on the text look as if it should toggle.
          <div className="flex shrink-0 items-center gap-2 text-sm">
            <span className="text-muted-foreground">Master Switch</span>
            <Switch
              checked={meta.enabled}
              disabled={globalSaving}
              onCheckedChange={toggleGlobal}
              aria-label="Global push switch"
            />
          </div>
        )}
      </div>

      {meta && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatTile label="Channel" value={`${meta.stats.channels_on} / ${meta.stats.channels}`} hint="Enabled / Total" />
          <StatTile label="Delivered today" value={String(meta.stats.sent_today)} />
          <StatTile label="Pending" value={String(meta.stats.pending)} />
          <StatTile label="Failed" value={String(meta.stats.failed)} tone={meta.stats.failed > 0 ? "red" : undefined} />
          <StatTile
            label="Longest backlog"
            value={formatBacklog(meta.stats.backlog_age_ms)}
            // The age of the backlog is far more useful than its size: a backlog of 3 could be anything from 3 seconds to 3 hours old.
            hint={meta.stats.backlog_age_ms > 5 * 60_000 ? "Push may be stuck" : undefined}
            tone={meta.stats.backlog_age_ms > 5 * 60_000 ? "red" : undefined}
          />
        </div>
      )}

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="text-base">Global settings</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="n-base">Callback URL</Label>
            <Input
              id="n-base"
              placeholder="https://artex.example.com"
              value={baseURL}
              onChange={(e) => setBaseURL(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">URL that the “View Details” button in messages points to. Leaving empty omits the button.</p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="n-digest">Aggregation interval (minutes)</Label>
            <Input
              id="n-digest"
              type="number"
              min={1}
              max={1440}
              placeholder="30"
              value={digestMin}
              onChange={(e) => setDigestMin(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">Effective only for channels in “aggregation” mode.</p>
          </div>
          <div className="sm:col-span-2">
            <Button onClick={saveGlobal} disabled={globalSaving}>
              Save global settings
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs value={tab} onValueChange={(v) => setTab(v as "channels" | "deliveries")} className="flex flex-col gap-4">
        <TabsList>
          <TabsTrigger value="channels">Channel</TabsTrigger>
          <TabsTrigger value="deliveries">Delivery records</TabsTrigger>
        </TabsList>

        <TabsContent value="channels">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <button
              type="button"
              onClick={openAdd}
              className="text-foreground/70 border-foreground/70 hover:bg-muted/60 hover:shadow-sm flex min-h-[130px] flex-col items-center justify-center gap-2 rounded-xl border border-dashed transition"
            >
              <PlusIcon className="size-6" />
              <span className="text-sm">Add channel</span>
            </button>

            {channels.map((ch) => (
              <Card
                key={ch.id}
                onClick={() => openEdit(ch)}
                className="hover:border-primary/60 cursor-pointer gap-3 transition hover:shadow-sm"
              >
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <BellIcon className="text-muted-foreground size-4 shrink-0" />
                    <CardTitle className="truncate text-base">{ch.name}</CardTitle>
                    {/* The entire card is clickable (enters edit), so these two controls must each stop propagation,
                        Otherwise toggles/delete will also trigger edit. Attach stopPropagation to the control itself
                        on the element itself, rather than wrapping in a div: wrapping in a div creates a static element that appears interactive but isn’t
                        role” static element, which triggers a11y warnings and is semantically incorrect. */}
                    <div className="ml-auto flex items-center gap-2">
                      <Switch
                        checked={ch.enabled}
                        onCheckedChange={() => toggleEnabled(ch)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label="Enable"
                      />
                      <Button
                        size="icon"
                        variant="outline"
                        aria-label="Delete"
                        onClick={(e) => {
                          e.stopPropagation();
                          // void explicitly discards the Promise: removeChannel catches and toasts itself,
                          // so there is no need to await here (onClick is not async).
                          void removeChannel(ch);
                        }}
                      >
                        <Trash2Icon className="text-destructive" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="grid gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">{KIND_LABEL[ch.kind] ?? ch.kind}</Badge>
                    <Badge variant="outline">{ch.mode === "digest" ? "Aggregate" : "Real-time"}</Badge>
                    {!ch.enabled && <Badge variant="outline">Disabled</Badge>}
                  </div>
                  <FilterSummary filter={ch.filter} />
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="deliveries">
          <DeliveryList channels={channels} />
        </TabsContent>
      </Tabs>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full data-[side=right]:sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : "Add notification channel"}</SheetTitle>
            <SheetDescription>
              {KIND_LABEL[form.kind] ?? form.kind}
              {defaultRate > 0 ? ` · Default rate limit ${defaultRate} items/minute` : " · No rate limit"}
            </SheetDescription>
          </SheetHeader>

          <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label>Channel type</Label>
                <Select
                  value={form.kind}
                  onValueChange={(v) => {
                    // Changing type means a different set of credential fields, so the old config must not be merged in.
                    setF({ kind: v, config: {} });
                  }}
                  disabled={!!editing}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(meta?.kinds ?? []).map((k) => (
                      <SelectItem key={k.kind} value={k.kind}>
                        {KIND_LABEL[k.kind] ?? k.kind}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {editing && (
                  <p className="text-muted-foreground text-xs">
                    Channel type cannot be changed; changing it requires a new set of credentials; please create a new channel.
                  </p>
                )}
              </div>

              <div className="grid gap-2">
                <Label htmlFor="n-name">Channel name</Label>
                <Input
                  id="n-name"
                  placeholder="Incident response group / daily broadcast group"
                  value={form.name}
                  onChange={(e) => setF({ name: e.target.value })}
                />
              </div>

              {fields.length === 0 ? (
                <p className="text-muted-foreground text-sm">
                  The form for this channel is not defined (frontend missing CHANNEL_FIELDS entry); please complete it and try again.
                </p>
              ) : (
                fields.map((d) => (
                  <ConfigField
                    key={d.key}
                    def={d}
                    value={form.config[d.key]}
                    isSecret={secretKeys.has(d.key)}
                    onChange={(v) => setCfg(d.key, v)}
                  />
                ))
              )}

              <div className="grid gap-2">
                <Label>Push timing</Label>
                <Select value={form.mode} onValueChange={(v) => setF({ mode: v as "realtime" | "digest" })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="realtime">Real-time · Send each vulnerability as a separate message</SelectItem>
                    <SelectItem value="digest">Aggregate · Merge into a single message per interval</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-muted-foreground text-xs">
                  To have \“high-risk real-time, others summarized\”, create two channels: one real-time with high-risk threshold, one summary with no level limit.
                </p>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="n-rate">Rate limit (items/minute)</Label>
                <Input
                  id="n-rate"
                  type="number"
                  min={0}
                  placeholder={defaultRate > 0 ? String(defaultRate) : "0 = No limit"}
                  value={form.ratePerMin}
                  onChange={(e) => setF({ ratePerMin: e.target.value })}
                />
                <p className="text-muted-foreground text-xs">
                  Leave empty to use channel default; 0 means no rate limit. Exceeding limit won’t drop messages, only delays sending.
                </p>
              </div>

              <div className="border-t pt-4">
                <p className="mb-3 text-sm font-medium">Filter rule (empty = no filter)</p>
                <div className="grid gap-4">
                  <div className="grid gap-2">
                    <Label>Minimum level</Label>
                    <Select
                      value={form.minSeverity || "all"}
                      onValueChange={(v) => setF({ minSeverity: v === "all" ? "" : v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITY_OPTIONS.map((o) => (
                          <SelectItem key={o.value || "all"} value={o.value || "all"}>
                            {o.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-inc">Only push these vulnerability types</Label>
                    <Textarea
                      id="n-inc"
                      placeholder={"SQLInjection\nCommand execution"}
                      value={form.includeText}
                      onChange={(e) => setF({ includeText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">
                      One keyword per line, case-insensitive substring match. Leave empty = all types.
                    </p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-exc">Exclude these vulnerability types</Label>
                    <Textarea
                      id="n-exc"
                      placeholder={"Information leakage"}
                      value={form.excludeText}
                      onChange={(e) => setF({ excludeText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">Exclusion takes precedence over inclusion; when both match, it is excluded.</p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-tasks">Restrict to tasks ID</Label>
                    <Input
                      id="n-tasks"
                      placeholder="1, 2, 3"
                      value={form.taskIDsText}
                      onChange={(e) => setF({ taskIDsText: e.target.value })}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-assets">Restrict to assets ID</Label>
                    <Input
                      id="n-assets"
                      placeholder="10, 11"
                      value={form.assetIDsText}
                      onChange={(e) => setF({ assetIDsText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">Task/asset, leave empty = any; if filled, must intersect with vulnerabilities.</p>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <Switch
                      checked={form.onStatusChange}
                      onCheckedChange={(v) => setF({ onStatusChange: v })}
                      aria-label="Receive status changes"
                    />
                    Also push on vulnerability disposition status change (real-time mode only)
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 text-sm">
                <Switch checked={form.enabled} onCheckedChange={(v) => setF({ enabled: v })} aria-label="Enable" />
                Enable this channel
              </div>
            </div>

            <div className="flex gap-2 pt-2 pb-6">
              <Button onClick={saveForm} disabled={saving}>
                {editing ? "Save" : "Add"}
              </Button>
              {editing && (
                <Button variant="outline" onClick={testChannel} disabled={testing}>
                  <SendIcon /> Send test message
                </Button>
              )}
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
