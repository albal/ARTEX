package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// This file covers doJSON's HTTP-level error grading.
//
// Why test it separately: each channel adapter only handles the platform's own business error codes (DingTalk errcode,
// Feishu code, Telegram's ok field), whereas the **HTTP-level** grading is done uniformly by doJSON;
// the two are independent lines of defence. Without this one, a relay gateway returning 503 would be treated as a permanent failure
// and retries abandoned outright, while a 403 would be treated as retryable and pointlessly backed off three times.

func replyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoJSONClassifiesHTTPStatus(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		permanent bool
	}{
		{"200 success is not an error", 200, false},
		{"429 rate limit is retryable", 429, false},
		{"408 request timeout is retryable", 408, false},
		{"500 server error is retryable", 500, false},
		{"502 bad gateway is retryable", 502, false},
		{"503 service unavailable is retryable", 503, false},
		{"400 bad request is permanent", 400, true},
		{"401 authentication failure is permanent", 401, true},
		{"403 forbidden is permanent", 403, true},
		{"404 not found is permanent", 404, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := replyServer(t, tc.status, `{"detail":"upstream says no"}`)
			_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("2xx should not be an error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("non-2xx should be an error")
			}
			if got := IsPermanent(err); got != tc.permanent {
				t.Fatalf("permanent judgement wrong for HTTP %d: want %v got %v (%v)",
					tc.status, tc.permanent, got, err)
			}
			// The status code must appear in the error, otherwise users cannot tell whether they misconfigured it or the peer is down.
			// The number is asserted rather than Go's StatusText: the number is the part that is language-independent
			// and can be asserted reliably.
			if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("the error message should include HTTP status code %d, got %v", tc.status, err)
			}
		})
	}
}

// TestDoJSONIncludesResponseSnippet covers snippet: the peer's error description must be brought back,
// otherwise users only know "it failed", not why the peer refused.
func TestDoJSONIncludesResponseSnippet(t *testing.T) {
	srv := replyServer(t, 400, `{"error":"invalid webhook token"}`)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should be an error")
	}
	if !strings.Contains(err.Error(), "invalid webhook token") {
		t.Errorf("the error message should bring back the peer's description, got %v", err)
	}
}

// TestDoJSONSnippetIsSingleLineAndBounded constrains the shape of snippet:
// the peer's response goes verbatim into the last_error column and the frontend table, and multiple lines/excessive length would break the layout and payload.
func TestDoJSONSnippetIsSingleLineAndBounded(t *testing.T) {
	// A response with newlines, tabs and 5000 characters of overlong content.
	long := strings.Repeat("x", 5000)
	srv := replyServer(t, 500, "line1\nline2\r\n\tline3 "+long)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should be an error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("the error message should be squashed onto one line, got %q", msg)
	}
	// snippet is capped at 200 characters + a fixed prefix, so the total must be far smaller than the raw response.
	if len(msg) > 400 {
		t.Errorf("error message too long (%d bytes); it should be truncated by snippet: %q", len(msg), msg)
	}
}

// TestDoJSONRejectsOversizedResponse confirms that reading is capped: when the peer misbehaves and returns huge content
// the whole response must not be read into memory (every entry in the delivery history stores a copy of last_error).
func TestDoJSONRejectsOversizedResponse(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // 1 MiB
	srv := replyServer(t, 400, huge)
	_, err := doJSON(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("should be an error")
	}
	if len(err.Error()) > 400 {
		t.Errorf("an oversized response should be read with a limit and truncated; error message length %d", len(err.Error()))
	}
}
