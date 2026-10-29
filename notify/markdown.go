package notify

import (
	"fmt"
	"strings"
)

// This file is the shared message rendering for the "Markdown family" of channels (DingTalk, WeCom).
// Feishu uses card JSON, Telegram uses HTML and email uses HTML, each rendered in its own adapter.

// maxAssetsShown is the maximum number of assets listed in a message. A vulnerability may be anchored to dozens of assets,
// and listing them all would swamp the message with no informational value: nobody reads the fourth domain onwards in an IM.
const maxAssetsShown = 3

// maxSummaryRunes is how many characters the summary is compressed to. An IM message is "a prompt to go and look at the details",
// not the report itself; the full content is in the platform.
const maxSummaryRunes = 120

// markdownReservedBytes is reserved for the message header (digest line + severity breakdown + possible truncation notice)
// and footer (platform link). When packing whole items this is deducted from the budget so the header and footer are never cut off;
// once they are cut, readers cannot even tell "which batch this is or how many items were not shown".
const markdownReservedBytes = 320

// markdownEscape escapes markdown metacharacters.
//
// Why this is required: vulnerability titles, summaries, types and asset display names all come from **untrusted sources**:
// titles and summaries come from model output (and the model reads the target's responses), while asset urls are full URLs
// obtained by scanning (including target-controlled query strings). Without escaping, a vulnerability titled
//
//	Login form SQL injection\n[URGENT: click here to verify your account](http://attacker.tld)
//
// would render in a security engineer's DingTalk/Feishu as a **clickable external link**; and
// `![](http://attacker.tld/beacon)` would be fetched by the client when rendered, announcing
// "this vulnerability has been viewed" and leaking the reader's IP. Even with harmless content, injected bold text or
// block quotes can push the critical vulnerabilities below out of view.
//
// The escape set covers the characters for headings/links/emphasis/lists/quotes/strikethrough that change structure or produce clickable
// elements. `\` must be handled first, otherwise the backslashes added later would be escaped again.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText squashes untrusted text onto a single line and escapes it, for use in markdown bodies.
// Single-lining is the other half beyond escaping: a newline by itself can fake a new list item or block quote,
// and escape characters cannot stop that.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns the message title (the IM platform's title bar/card title), as **unescaped raw text**.
//
// Escaping is deliberately not done here: this title is shared by renderers in four contexts: markdown bodies, Telegram's
// HTML, Feishu cards' plain_text, and the generic webhook's JSON and email subjects. Each context
// has different escaping rules (markdown escapes in HTML leave visible backslashes, and in JSON they pollute
// the data), so escaping must be the responsibility of each output; see writeItem / feishuItemLines /
// telegramEscape. Markdown escaping was once added to the shared function, and Telegram messages ended up
// showing visible backslashes like `\(1\)`.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("Vulnerability digest · %d in total", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "Vulnerability notification"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody renders the message body and returns the body and the **number of items actually written**.
//
// The returned kept is the number of items this delivery really delivered, and the caller marks only the first kept items as
// delivered; items kept out by the channel's length limit must wait for the next batch rather than being
// marked successful along with them. This is exactly where "silent loss" comes from: the message was truncated but the delivery record says everything was delivered,
// and there is nowhere to see that the second half was never sent.
//
// maxBytes<=0 means no limit.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// A single message is sent even if it is too long (the final truncation is the backstop): part of a vulnerability's information
		// is better than sending nothing at all.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[View all in the platform](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro renders the start of a digest message: time window, count and severity breakdown.
// With these, whoever receives the digest can judge whether the batch needs immediate attention without opening the platform.
//
// items are the items **actually fitted**, total is the number the batch should have. When the two differ it must say plainly
// "how many more are in the next message"; otherwise readers would assume the number in the header is everything,
// and the items that were never sent would not exist anywhere in the interface.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**%d new vulnerabilities in the last %d minutes**", total, m.WindowMinutes)
	} else {
		fmt.Fprintf(&b, "**%d new vulnerabilities**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, " (this message shows the first %d; the remaining %d follow in the next message)", len(items), extra)
	}
	// Give the breakdown by severity so readers can see at a glance whether there are critical items. Only items **actually included in this message**
	// are counted, so "Critical 3" matches the items that can be counted below.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders a single vulnerability item.
//
// prefix is the sequence number in a digest list; single=true renders the full version (with summary and link back),
// while a digest list renders only a one-line summary, otherwise a 50-item digest would become a long document.
//
// All externally sourced content (title/type/assets/summary) goes through markdownText:
// single-lined + escaped. The link back is built from the administrator-configured public_base_url, is not untrusted content,
// and must be a clickable link, so it is output as is.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// Digest mode: one line, with assets and summary compressed after it.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**Status change**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**Type**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**Assets**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**Summary**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[View details](%s)\n", it.DetailURL)
	}
}
