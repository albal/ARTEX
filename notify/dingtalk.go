package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements the DingTalk custom bot.
//
// Platform characteristics (which determine the trade-offs in this implementation):
//   - Each bot is rate limited to 20 messages/minute, and excess messages are silently dropped (HTTP may still be 200),
//     so rate limiting must be done on the client; see DefaultRatePerMin.
//   - Security settings are one of three: signing / custom keywords / IP allowlist. Signing is the only option that does not depend
//     on message content, so only signing is supported (a bare webhook with none of the three enabled is supported too).
//   - Success and failure both return HTTP 200, distinguished by errcode in the body; not checking errcode
//     would record failed deliveries as successful.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// A DingTalk webhook URL contains the access_token and is itself a credential, so it is masked as a whole.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// The destination is the DingTalk webhook URL itself; changing the address requires the signing secret to be restated for the new address.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("webhook URL is missing")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	return nil
}

// Send delivers one message. A single item with a link back uses an ActionCard (with a button); otherwise markdown is used.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// DingTalk markdown bodies have no explicit byte limit, but a limit is still applied as protection against abnormally bloated evidence fields.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "View details",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk hides business errors inside 200 responses.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse DingTalk response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 is a signature check failure and 310000 a keyword mismatch: both are configuration errors
		// that retrying will not fix.
		return 0, Permanent(fmt.Errorf("DingTalk returned error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends the timestamp and sign parameters to the webhook according to the official signing rules.
//
// Rule: string to sign = timestamp + "\n" + secret, the HMAC-SHA256 **key is also the secret**,
// and the result is base64-encoded then URL-encoded. timestamp is in milliseconds. When secret is empty it is returned unchanged,
// to support bots without signing enabled.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// err is not passed through: url.Parse's error text contains the full address (including the access_token).
		return "", fmt.Errorf("failed to parse webhook URL: %s", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks that an address is usable and uses a supported scheme, and checks literal IP targets for internal addresses.
//
// Two subtleties:
//
//  1. **The error message must be redacted**. url.Parse itself returns a *url.Error whose Error() includes
//     **the full original address**, and these providers' addresses have credentials embedded in them (DingTalk access_token,
//     WeCom key, Telegram bot token, Feishu hook id). This once did a plain `return err`,
//     so the "invalid address format" error carried the credentials out, into the test endpoint's 400 response,
//     the last_error stored with every delivery, the server logs and the delivery history endpoint.
//
//  2. **Literal IPs are checked for internal addresses immediately**, while domains are left to the dial stage (blockInternalDial is where it finally
//     takes effect, and it also covers DNS rebinding). It is done once here so a warning is given when the configuration is saved,
//     rather than waiting for the first failed delivery.
//
// Restricting the scheme is defensive: things like file:// and gopher:// would make http.Client behave
// unexpectedly (they are already stopped by the scheme check, but there is no reason to open up that surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("address cannot be parsed (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https are supported, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("hostname is missing")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("refusing to deliver to a local/link-local address %s (if you really need to deliver to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}
