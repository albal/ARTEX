package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit is the hard limit on WeCom group bot markdown content (bytes, not characters).
// It is the tightest limit of all six channels and the main reason TruncateBytes exists.
const weComMarkdownLimit = 4096

// weComChannel implements the WeCom group bot.
//
// Platform characteristics:
//   - Authentication is solely by the key in the URL, with no signing support, so the webhook URL itself is the entire credential.
//   - markdown content is limited to 4096 **bytes**, and anything longer is rejected outright (not truncated). At 3 bytes per CJK character
//     that leaves room for only a little over a thousand characters, so truncation must be done on the client.
//   - Rate limited to 20 messages/minute, likewise held in check by client-side rate limiting.
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// WeCom has only one credential, the webhook (the key in the URL), and it does not support signing:
// the whole address is the entire credential, and no other field needs masking.
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// WeCom has only the one webhook field, which is both the destination and the credential, so there is no such thing as "credentials left behind after changing the address".
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("webhook URL is missing")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// A digest batch can be long (50 items × one line each + prefix), so 4096 bytes is easily exceeded.
	// Truncation is done here rather than relying on the platform's error: a rejection means the whole batch is lost, whereas truncation delivers at least the first few items.
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse WeCom response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 means the API call limit was exceeded; the platform's rate limit window rolls, so retrying after a backoff works,
		// and it is explicitly classed as retryable. Reaching here means the client's rate_per_min is set too aggressively;
		// retrying is only a backstop, and the real fix is to lower that channel's rate limit.
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom rate limited %d: %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 means the webhook key is invalid: a permanent failure that retrying will not fix.
		return 0, Permanent(fmt.Errorf("WeCom returned error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}
