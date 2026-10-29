package notify

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// This file covers two related hardening measures:
//   ① delivery addresses must not use the server as a springboard into the internal network / cloud metadata (SSRF)
//   ② address validation errors must not carry out the credentials in the address
//
// About the test environment: many tests in this package use httptest fake receivers on 127.0.0.1, which the guard blocks by default.
// So TestMain turns AllowLocalTargetsEnv on globally, and every SSRF test below
// explicitly clears it again to assert the **refuse by default** behaviour.

func TestMain(m *testing.M) {
	// Let ordinary tests reach the local fake receivers; the SSRF tests clear it temporarily themselves.
	_ = os.Setenv(AllowLocalTargetsEnv, "1")
	os.Exit(m.Run())
}

// TestDialGuardRejectsLoopbackByDefault is the core assertion of the SSRF protection:
// with the default configuration, delivery to a loopback address must be refused **at the connection layer**.
func TestDialGuardRejectsLoopbackByDefault(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "") // escape hatch off = default behaviour
	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("delivery to a loopback address should not be allowed by default")
	}
	if hit {
		t.Fatal("the request reached the local service; the guard did not take effect")
	}
	// The error message must guide users on how to allow it (a local SMTP relay is a legitimate configuration).
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("the refusal message should explain how to allow it explicitly: %v", err)
	}
}

// TestDialGuardAllowsLoopbackWhenOptedIn is the reverse case: once explicitly enabled it must work,
// otherwise legitimate deployments such as a local postfix / internal relay would be crippled by a blanket ban.
func TestDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"}, Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("delivery should work once explicitly allowed: %v", err)
	}
}

func TestIsBlockedDialIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"169.254.169.254", // the cloud metadata endpoint, the main reason this function exists
		"169.254.1.1", "fe80::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"::ffff:127.0.0.1", // the IPv4-mapped form must be converted back before checking, otherwise it is a bypass
		"",
	}
	for _, s := range blocked {
		if !isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be refused", s)
		}
	}
	// RFC1918 private networks are **deliberately allowed**: self-hosted Mattermost / SMTP relays on internal networks are a common legitimate use.
	// This assertion pins down that trade-off: if someone later adds a private network check in passing, this will fail,
	// forcing a conscious decision (rather than silently crippling a whole set of deployments).
	allowed := []string{"10.0.0.5", "172.16.3.4", "192.168.1.10", "8.8.8.8", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedDialIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed (private networks are common legitimate delivery targets)", s)
		}
	}
}

// TestValidateHTTPURLRejectsLiteralPrivateTargets covers the early warning at configuration time:
// literal IPs should be refused when saved, not when the first delivery fails.
func TestValidateHTTPURLRejectsLiteralPrivateTargets(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/hook",
	} {
		if err := validateHTTPURL(raw); err == nil {
			t.Errorf("%s should be refused at configuration time", raw)
		}
	}
	// Public and private addresses pass as normal (private ones are left to the dial stage, which does not block them).
	for _, raw := range []string{"https://oapi.dingtalk.com/robot/send", "http://10.0.0.9/hook"} {
		if err := validateHTTPURL(raw); err != nil {
			t.Errorf("%s should pass validation: %v", raw, err)
		}
	}
}

// TestValidateHTTPURLErrorNeverLeaksCredentials covers the branch the audit pointed out I missed in the previous round.
//
// When url.Parse **fails** it returns a *url.Error whose Error() contains the full original address. In the previous round I only
// redacted the error returned by http.Client.Do and missed this one; and the "permanent failure path" tests added then
// (file://, gopher://, ftp://) can all be parsed successfully by url.Parse and take the scheme branch,
// so all green proved nothing about this path: it was a false assurance.
func TestValidateHTTPURLErrorNeverLeaksCredentials(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/%zz?access_token=" + leakProbeToken,         // invalid percent escape
		"https://a.example.com:port/x?access_token=" + leakProbeToken, // non-numeric port
		"http://[::1?access_token=" + leakProbeToken,                  // unbalanced bracket
	}
	for _, raw := range cases {
		// First confirm that this input **really** makes url.Parse fail. Without this step the test might
		// take another branch without anyone noticing (which is exactly where the previous round's false assurance came from).
		if _, err := url.Parse(raw); err == nil {
			t.Errorf("%q should have failed to parse; otherwise this test does not cover the target branch", raw)
			continue
		}
		err := validateHTTPURL(raw)
		if err == nil {
			t.Errorf("%q should fail validation", raw)
			continue
		}
		assertNoSecret(t, err.Error(), leakProbeToken)
	}
	// Confirm the channel layer's wrapping does not carry the address out either.
	t.Setenv(AllowLocalTargetsEnv, "")
	err := (dingTalkChannel{}).Validate(map[string]any{"webhook": cases[0]})
	if err == nil {
		t.Fatal("an invalid address should fail validation")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestEmailDialGuardRejectsLoopbackByDefault covers the SMTP channel's dial guard.
//
// The email channel once used a bare net.Dialer, the only gap in the whole SSRF protection: a host of
// 169.254.169.254 or 127.0.0.1 could be connected to directly, and when the smtp.NewClient handshake failed it wrapped
// the line returned by the peer into the error, echoed via last_error by the delivery history endpoint: exactly the semi-blind read primitive
// the other channels had already closed; the timing difference between "connection refused" and "timeout" could also be used to probe ports.
//
// This package's TestMain turns AllowLocalTargetsEnv on globally (many tests use fake receivers on 127.0.0.1),
// so this test must clear it itself; otherwise it would pass whether or not the guard was there,
// which is exactly why the gap was never caught by any test in the first place.
func TestEmailDialGuardRejectsLoopbackByDefault(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "") // escape hatch off = default behaviour
	_, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil {
		t.Fatal("email delivery to a loopback address should not be allowed by default")
	}
	// The connection should never be established: the guard stops it in the Control hook, and EHLO is never sent.
	if f.sawCommand("EHLO") || f.sawCommand("HELO") {
		t.Fatal("the SMTP session was established; the guard did not take effect")
	}
	// The error message must guide users on how to allow it (a local postfix relay is a legitimate configuration).
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("the refusal message should explain how to allow it explicitly: %v", err)
	}
}

// TestEmailDialGuardAllowsLoopbackWhenOptedIn is the paired reverse case: once explicitly enabled,
// delivery must work normally. Self-hosted internal SMTP / local relays are very common deployments, and the guard must not be a blanket ban.
func TestEmailDialGuardAllowsLoopbackWhenOptedIn(t *testing.T) {
	f := newFakeSMTP(t)
	cfg := emailCfg(t, f, nil)

	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := (emailChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("local SMTP delivery should work once explicitly allowed: %v", err)
	}
	if !f.sawCommand("EHLO") {
		t.Fatal("no EHLO seen; the session was never really established")
	}
}
