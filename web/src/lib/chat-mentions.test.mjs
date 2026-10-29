import assert from "node:assert/strict";
import test from "node:test";
import { activeMention, mentionSearch, mentionToken, selectedMentions } from "./chat-mentions.ts";

test("mention trigger handles cursor placement without hijacking email", () => {
  assert.equal(activeMention("user@example.com", 16), null);
  assert.equal(activeMention("Selected @[Vulnerability#1 X]", 26), null);
  assert.deepEqual(activeMention("See @Vuln and the rest", 9), { start: 4, end: 9, query: "Vuln" });
  assert.equal(activeMention("@Vuln\nnext line", 10), null);
});

test("categories, aliases, IP and keyword search", () => {
  assert.equal(mentionSearch("").categories.length, 9);
  assert.equal(mentionSearch("vul").categories[0].kind, "finding");
  assert.equal(mentionSearch("vulnerability").kind, "finding");
  assert.equal(mentionSearch("vulnerability SQL injection").query, "SQL injection");
  assert.equal(mentionSearch("ip 192.0.2.1").kind, "ip");
  assert.equal(mentionSearch("api GET /api").query, "GET /api");
  assert.equal(mentionSearch("acme.com").kind, "");
});

test("tokens roundtrip labels and removing one reference preserves its neighbours", () => {
  const first = mentionToken({ kind: "finding", id: 12, label: "Title[1]\nDescription" });
  const second = mentionToken({ kind: "ip", id: 13, label: "192.0.2.1" });
  const value = `Analyse ${first} and ${second}`;
  const selected = selectedMentions(value);
  assert.equal(selected.length, 2);
  assert.equal(selected[0].label, "Vulnerability #12 · Title(1) Description");
  const next = value.slice(0, selected[0].start) + value.slice(selected[0].start + selected[0].token.length);
  assert.equal(selectedMentions(next)[0].token, second);
});
