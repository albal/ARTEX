package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes truncates s to at most max bytes, ensuring the result is valid UTF-8 and no character is split.
//
// Why it must cut on character boundaries: WeCom group bot markdown has a hard limit of 4096 **bytes** (not
// characters), and a CJK character takes 3 bytes. Slicing directly by byte would cut a character in half and produce invalid
// UTF-8, which the platform either rejects outright or displays as garbled boxes. The approach here is to step back from the budget position
// to the nearest rune start byte (utf8.RuneStart identifies continuation bytes 0b10xxxxxx).
//
// max<=0 means no limit. An ellipsis is appended after truncation unless max is too small to hold it.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max is shorter than the ellipsis: drop the ellipsis and truncate plainly, so the result cannot exceed max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine squashes multi-line text onto a single line: it collapses all whitespace, then truncates by character count.
// Used for IM message title lines, since summaries often contain newlines that would break a table/title layout.
// max<=0 means no length limit.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes truncates s to at most max characters (not bytes), appending an ellipsis when it is over.
// max<=0 means no limit.
//
// The difference from TruncateBytes is the platform's measure: WeCom limits by bytes, Telegram by characters.
// Using the wrong measure raises no error; it just makes messages much shorter than expected (a CJK character = 3 bytes,
// so cutting at 4096 bytes leaves only about 1365 characters), so both functions must be kept and chosen per channel.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML truncates an HTML fragment by character count, ensuring no half tags are produced.
//
// Truncating HTML directly by character would produce broken tags like `<a href="htt`, which the platform parser either
// rejects as a whole message or swallows the following body text as an attribute value. The approach here: truncate by character first,
// then check whether the tail has an unclosed `<`, and if so step back to before it.
//
// Tag balancing (adding </b> and the like) is not done: Telegram's HTML parser closes unclosed tags automatically,
// and implementing balancing ourselves would mean handling quotes in attributes, comments and self-closing tags, which is out of proportion to the benefit.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the tail is a fragment starting with `<` (no `>` after the last `<`), step back to before the `<`.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// If the tail is a truncated HTML entity (such as `&amp;` cut to `&amp`), step back as well.
	// An entity fragment may get the **whole message** rejected by a parser that only accepts entities; a digest exceeding
	// the length limit is common enough already, and it is not worth losing the whole notification over it.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount works out how many items fit **completely** within the budget, so digest messages are packed in whole items.
//
// Why pack whole items rather than render the full text and then truncate: truncation would make the second half of the items vanish into thin air,
// while their delivery records would still be marked as delivered; nothing in the message or the delivery history would show it,
// and the vulnerabilities would simply disappear. With whole-item packing, items that do not fit stay in the database as the next batch,
// and the kept the caller receives is the number this message really delivered.
//
// Parameters: maxSize<=0 means no limit; reserve is the amount reserved for the message header/footer;
// size does the measuring (each platform measures differently: WeCom/DingTalk by bytes, Telegram by characters;
// using the wrong measure raises no error, it just squeezes CJK-heavy messages far below the limit);
// render renders item idx as its actual text: the length varies with the content and cannot be estimated.
//
// Returns at least 1 (as long as there are items). Even a single extremely long item must be sent, with the caller's
// final truncation as the backstop, otherwise one overlong vulnerability would leave the whole batch stuck permanently.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize are packItemCount's two measures, named so that call sites do not end up
// with bare func(s string) int closures, which would make it hard to see at a glance which measure is used.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine renders the asset list as one line of display text; above limit the rest are omitted and the total is noted.
// A vulnerability may be anchored to dozens of assets, and listing them all would swamp the message.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " and " + itoa(len(assets)-limit) + " more"
}

// itoa is a short alias for strconv.Itoa, used only for building display text, to avoid importing strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
