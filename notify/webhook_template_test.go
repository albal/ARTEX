package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// This file locks in the **capability boundary** of the generic webhook template.
//
// This is the only place in the whole package where "a user-supplied string is evaluated as code", so it must be clear what it can do
// and what it cannot, with tests pinning those properties down; otherwise someone might later add a method to the template context in passing,
// or a readFile to the FuncMap, and the capability surface would grow silently while the diff looked
// like nothing more than a harmless little function.

// TestTemplateContextHasNoMethods is the most important one.
//
// text/template calls exported methods ({{.Foo}} can both read a field and call a method). So as soon as the template context
// can reach **any** type with exported methods, those methods are exposed to the template author.
// This feature's context is deliberately pure data (exported fields only, zero methods).
//
// If this fails: someone has added a method to webhookTemplateData / webhookItem.
// Before allowing it, think hard about whether the template could use that method to read things that should not be exposed.
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d methods (%s): text/template can call them, "+
				"which opens those methods' capabilities to the template author", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal locks in the set of functions exposed to templates.
//
// Every extra function in the FuncMap is an extra capability. Currently there are only json / jsons, which serialise values
// into JSON fragments: they cannot read files, make requests or run commands.
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the template function set changed: got %v, want %v. Before adding a function, confirm it does not widen the capability surface"+
			" (no reading or writing files, no network requests, no running commands)", got, want)
	}
}

// TestTemplateCannotReachUnknownData covers out-of-bounds access in templates:
// accessing something that does not exist must fail rather than echo something, and the failure message must not carry internal data out.
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a field that does not exist should be an error")
	}
	// The error must not contain real content from the template context (the vulnerability title/summary).
	for _, leak := range []string{"SQL injection", "parameter id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the template error leaked message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently: a broken template is a configuration error that retrying will not fix.
// If it were judged retryable, a bad template would waste three rounds of backoff on every delivery.
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("a template syntax error should be caught when saved")
	}
	// Even if validation is bypassed and it is delivered directly, it must be judged permanent rather than retried repeatedly.
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a bad template should be judged permanent, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON covers the constraint that "the template must render valid JSON".
// It incidentally blocks uses such as "generating plain text with the template to trigger another protocol".
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// A valid template passes.
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("a valid template should pass validation: %v", err)
	}
	// A non-JSON render must be rejected (rather than sent as is).
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a non-JSON render should be judged permanent, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("the error message should say it is a JSON problem, got %v", err)
	}
}
