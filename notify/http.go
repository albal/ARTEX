package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets decides whether messages may be delivered to loopback / link-local addresses.
//
// Refused by default. These address ranges are not where IM bots or public mail servers live, and what they can
// reach is sensitive: another service's management port on the same machine, and the cloud metadata endpoint
// (169.254.169.254, which can reveal instance credentials). Delivery addresses are configured by an administrator, but an admin session
// hijacked by XSS/CSRF, or a second person sharing the same JWT, could read response content back by changing the configuration:
// doJSON writes the first 200 bytes of a 4xx/5xx response body into last_error, and the delivery history endpoint
// echoes it back, which makes a semi-blind read primitive.
//
// But a "local SMTP relay" (postfix on 127.0.0.1:25) is a common self-hosted mail setup,
// and a blanket ban would leave people stuck. So rather than hard-coding an exception there is an explicit escape hatch:
// set ARTEX_NOTIFY_ALLOW_LOCAL=1 to allow it.
//
// It is exported as AllowLocalTargetsEnv so tests can turn it on explicitly: this package's and the server package's
// tests make heavy use of httptest fake receivers on 127.0.0.1, which would all be stopped by the guard otherwise.
const AllowLocalTargetsEnv = "ARTEX_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP reports whether the target IP is in an address range that is "not allowed for delivery by default".
//
// Only loopback, link-local (including cloud metadata at 169.254.169.254), unspecified and multicast are refused.
// RFC1918 private networks are **not** refused: self-hosted Mattermost / SMTP relays on internal networks are a very common legitimate use,
// and blocking them too would make the feature unusable in real environments. This trade-off is deliberate:
// the protection must stop the genuinely sensitive targets without crippling normal deployments.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) must be converted back to IPv4 before checking, otherwise it bypasses the check.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the Control hook of the http.Transport dialler, checking the target address **when the connection
// is established**.
//
// Why at the dial stage rather than only when the configuration is saved: this is where it finally takes effect.
// It covers both ways of bypassing config validation: DNS rebinding (resolving to a public IP during validation but
// to an internal one when actually connecting) and redirects (we already refuse cross-host redirects, but a same-host redirect
// could still point the path elsewhere).
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot resolve target address %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("refusing to deliver to a local/link-local address %s (if you really need to deliver to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport adds only a dial guard on top of the default Transport.
// Clone keeps all the default tuning (connection pool, HTTP/2, timeouts, proxy etc.),
// so adding one check does not change any other behaviour.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is the client shared by every channel delivery.
//
// It deliberately does **not** reuse the project's global egress proxy (GlobalProxy on the server side): that proxy is for penetration
// target traffic and is often an unstable tunnel, and notification availability should not be held hostage by the target network's instability.
// IM notifications can connect directly. The timeout is 15 seconds; a peer slower than that is effectively already in a failed state.
//
// Cross-host redirects are refused: this feature's delivery addresses are all of the "one fixed endpoint" form and normally never
// redirect to another host, while these providers' credentials (DingTalk's access_token, WeCom's key, Telegram's
// bot token) are **in the URL**, so following a cross-host redirect would hand the credentials to the redirect target. Same-host
// redirects (such as adding a trailing slash) are still allowed.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("refusing cross-host redirect (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit caps how much of the response body is read. A misbehaving peer may return huge content, and we only need
// the status code and a short error description to show in the delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns the response body (length-limited).
//
// When payload is nil an empty body is sent (for GET or platforms that do not require a body).
// Keys and values in headers are attached as is, for the generic webhook's custom headers.
//
// Error classification is this function's core responsibility: network-level failures and 5xx/408/429 are "retryable",
// other 4xx are "permanent failures"; retrying a 403 only writes the same error to the log three times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// A serialisation failure is a local bug (wrong config field type); retrying will not make it better.
			return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// Invalid URL: most likely the user entered the address wrongly, which is a permanent failure.
		// err must not be passed through here either: url.Parse's error text contains the full address.
		return nil, Permanent(fmt.Errorf("invalid request address: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refused, DNS failure, timeout: mostly transient faults, left to backoff retries.
		//
		// The error text must be redacted before it is passed on. Why: http.Client.Do returns a *url.Error,
		// whose Error() is `Op "full URL": underlying error`, and for these providers the credentials are **in the URL**
		// (DingTalk access_token, WeCom key, Feishu hook id, Telegram /bot<token>/).
		// Without redaction the credentials would flow along this error string to four places: notification_deliveries'
		// last_error (stored in plain text), the delivery history endpoint's response (**bypassing the channel config masking**),
		// the server logs, and the 502 text the test send endpoint returns to the frontend.
		return nil, fmt.Errorf("request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429 (rate limited) and 408 (timeout) are worth retrying; other 4xx are configuration or permission problems where retrying is pointless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("peer rate limited or timed out (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("peer service error (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("peer rejected the request (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet squashes a response body into a short single line for error messages. Responses may contain newlines and lots of whitespace,
// and putting that straight into last_error would break the layout of the delivery history page.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget squashes a delivery address into "scheme://host/…" for error messages.
//
// This is the package's only address redaction rule, and it is deliberately **blunt**: everything except the scheme and host
// is discarded. The reason is that there is no "general and safe" way to tell which part of a URL is the credential:
//
//	DingTalk  credential in the query      /robot/send?access_token=xxx
//	WeCom     credential in the query      /cgi-bin/webhook/send?key=xxx
//	Feishu    credential in the **last path segment** /open-apis/bot/v2/hook/<hook_id>
//	Telegram  credential in the **middle of the path** /bot<token>/sendMessage
//
// "Keeping only the useful part" would mean patching per channel, and missing any one of them would be a credential leak.
// Keeping the host is enough for diagnosis (DNS failure, connection failure and certificate problems can all be pinpointed),
// and which bot it is can be recognised from the masked suffix hint in the channel configuration.
//
// On a parse failure a fixed placeholder is returned; the raw string is never echoed back.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparseable address)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips the address from a transport-level error, keeping only the underlying cause.
//
// *url.Error has the structure {Op, URL, Err}, and Error() prints the URL as well.
// The Err field is taken explicitly here, bypassing its Error(); this is more reliable than string replacement after the fact,
// because replacement has to cope correctly with every URL-encoded/escaped variant and is easy to get wrong.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: unknown error", uerr.Op, host)
	}
	// Errors other than *url.Error (such as one returned by the redirect policy) may also carry an address, so they are redacted too.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces any http(s) addresses in a piece of text with their redacted form.
//
// Used as a fallback for errors where no structured fields are available (redirect policy errors, custom errors from third-party libraries).
// Only http/https prefixes are recognised, splitting on whitespace and quotes, since an address never contains those two kinds of character.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
