// Channel field table and config value parsing utilities.
//
// It is kept separate from the page because this is **data**, not a view: it describes which fields each channel has,
// which control each should use, and the two-way conversion between form text and config values (JSON).
// With it in its own file, adding a channel only requires changes here; the page itself does not need to change.
// Display names and descriptions of channel types. They live in the frontend because they only affect wording; the backend does not need to know.
export const KIND_LABEL: Record<string, string> = {
  dingtalk: "DingTalk",
  feishu: "Feishu",
  wecom: "WeChat Work",
  webhook: "Generic Webhook",
  telegram: "Telegram",
  email: "Email",
};

// Config field definitions for each channel.
//
// A frontend field table is deliberately kept here rather than having the backend send a schema: the backend is only responsible for
// Validate (required/format), while the UI needs layout and control types; the two are not concerned with the same thing.
// The only coupling point is secret_keys: which fields should be rendered as password fields is supplied by the backend,
// because only the channel implementation knows which values count as credentials (for WeCom the whole webhook is a credential,
// whereas for DingTalk it is just one secret). Missing an entry here when adding a channel only leaves the form blank;
// it does not fail silently (hasFields below will flag it).
export type FieldKind = "text" | "password" | "number" | "select" | "textarea" | "switch" | "kv" | "list";
export interface FieldDef {
  key: string;
  label: string;
  kind: FieldKind;
  placeholder?: string;
  help?: string;
  options?: { value: string; label: string }[];
}
export const CHANNEL_FIELDS: Record<string, FieldDef[]> = {
  dingtalk: [
    {
      key: "webhook",
      label: "Webhook Address",
      kind: "text",
      placeholder: "https://oapi.dingtalk.com/robot/send?access_token=...",
    },
    {
      key: "secret",
      label: "Signature key",
      kind: "password",
      help: "Fill when bot security setting is 'Signature'; leave empty if 'Custom keyword' is selected or security is disabled.",
    },
  ],
  feishu: [
    {
      key: "webhook",
      label: "Webhook Address",
      kind: "text",
      placeholder: "https://open.feishu.cn/open-apis/bot/v2/hook/...",
    },
    { key: "secret", label: "Signature verification key", kind: "password", help: "Fill when bot enables 'Signature verification', otherwise empty." },
  ],
  wecom: [
    {
      key: "webhook",
      label: "Webhook Address",
      kind: "text",
      placeholder: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...",
    },
  ],
  webhook: [
    { key: "url", label: "Target URL", kind: "text", placeholder: "https://your-endpoint.example.com/hook" },
    {
      key: "method",
      label: "Request method",
      kind: "select",
      options: [
        { value: "POST", label: "POST (With request body)" },
        { value: "PUT", label: "PUT (With request body)" },
        { value: "PATCH", label: "PATCH (With request body)" },
        { value: "GET", label: "GET (Without request body)" },
      ],
    },
    { key: "headers", label: "Custom request header", kind: "kv", help: "“Custom request header”, kind: “kv”, help: “One per line KEY=VALUE, e.g.” Authorization=Bearer xxx" },
    {
      key: "body_template",
      label: "Request body template",
      kind: "textarea",
      help:
        "Leave empty to use built-in default template. Variables: {{.Title}} {{.Batch}} {{.Count}} {{.HomeURL}} {{.SentAt}}, " +
        "Also under range .Items .Name/.VulnClass/.Severity/.Summary/.Assets/.DetailURL/.StatusLabel." +
        "Use for inserting strings {{json .Xxx}} rather than {{.Xxx}}, Otherwise quotes in the title will break JSON.",
    },
  ],
  telegram: [
    { key: "bot_token", label: "Bot Token", kind: "password", placeholder: "123456:ABC-DEF..." },
    { key: "chat_id", label: "Chat ID", kind: "text", placeholder: "-1001234567890" },
    {
      key: "base_url",
      label: "API Address",
      kind: "text",
      placeholder: "https://api.telegram.org",
      help: "Leave empty for official address; fill when using self-hosted Bot API proxy.",
    },
  ],
  email: [
    { key: "host", label: "SMTP Server", kind: "text", placeholder: "smtp.example.com" },
    {
      key: "port",
      label: "Port",
      kind: "number",
      placeholder: "587",
      help: "587 Use STARTTLS; enable 'Implicit TLS' for port 465.",
    },
    { key: "username", label: "Account", kind: "text" },
    { key: "password", label: "Password / Auth Code", kind: "password" },
    { key: "from", label: "Sender", kind: "text", placeholder: "artex@example.com" },
    { key: "to", label: "Recipient", kind: "list", help: "Separate multiple addresses with commas" },
    { key: "tls", label: "Implicit TLS", kind: "switch", help: "465 Port open; keep 587 closed (auto) STARTTLS)" },
  ],
};

export const SEVERITY_OPTIONS = [
  { value: "", label: "No limit" },
  { value: "low", label: "Low or higher risk" },
  { value: "medium", label: "Medium or higher risk" },
  { value: "high", label: "High or higher risk" },
  { value: "critical", label: "Severe only" },
];

export type ChannelForm = {
  name: string;
  kind: string;
  mode: "realtime" | "digest";
  enabled: boolean;
  ratePerMin: string;
  config: Record<string, unknown>;
  minSeverity: string;
  includeText: string;
  excludeText: string;
  taskIDsText: string;
  assetIDsText: string;
  onStatusChange: boolean;
};

export const emptyForm = (kind: string): ChannelForm => ({
  name: "",
  kind,
  mode: "realtime",
  enabled: true,
  ratePerMin: "",
  config: {},
  minSeverity: "",
  includeText: "",
  excludeText: "",
  taskIDsText: "",
  assetIDsText: "",
  onStatusChange: false,
});

// parseKV parses a textarea of "one KEY=VALUE per line".
export function parseKV(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const i = t.indexOf("=");
    if (i > 0) out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  }
  return out;
}
// parseIDs parses a comma/whitespace-separated list of ids.
export function parseIDs(text: string): number[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => Number(s))
    .filter((n) => Number.isFinite(n) && n > 0);
}
// parseKeywords parses a keyword list separated by lines/commas (vulnerability type names may contain spaces, so split on lines or commas).
export function parseKeywords(text: string): string[] {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}
