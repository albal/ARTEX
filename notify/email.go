package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// emailDialTimeout / emailSessionTimeout constrain connection set-up and the whole SMTP session respectively.
// net/smtp has no timeout mechanism of its own, so without these two a stuck peer would leave
// the delivery goroutine hanging there forever; and since the dispatcher processes serially on a single goroutine,
// that would bring the whole notification system to a halt.
const (
	emailDialTimeout    = 10 * time.Second
	emailSessionTimeout = 45 * time.Second
)

// emailChannel implements SMTP email delivery.
type emailChannel struct{}

func (emailChannel) Kind() string { return KindEmail }

// Email has no platform rate limit, but it should not be used to flood inboxes; a generous default is given.
func (emailChannel) DefaultRatePerMin() int { return 60 }

// Only the password is masked. The SMTP host, account and recipients are not secret, and masking them would only make editing harder.
func (emailChannel) SecretKeys() []string { return []string{"password"} }

// host/port decide which server the password is handed to; tls decides whether the transport is encrypted. A change to any of the three
// requires the password to be restated, which incidentally means "turning off TLS" must explicitly come with the credentials rather than being a casual change.
func (emailChannel) DestinationKeys() []string { return []string{"host", "port", "tls"} }

func (emailChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "host") == "" {
		return errors.New("SMTP server address is missing")
	}
	port := cfgInt(cfg, "port")
	if port <= 0 || port > 65535 {
		return errors.New("invalid SMTP port (must be 1-65535)")
	}
	if cfgString(cfg, "from") == "" {
		return errors.New("sender address is missing")
	}
	if len(cfgStrings(cfg, "to")) == 0 {
		return errors.New("at least one recipient address is required")
	}
	return nil
}

func (c emailChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	host := cfgString(cfg, "host")
	port := cfgInt(cfg, "port")
	from := cfgString(cfg, "from")
	to := cfgStrings(cfg, "to")
	username := cfgString(cfg, "username")
	password := cfgString(cfg, "password")
	implicitTLS := cfgBool(cfg, "tls")

	msg, err := buildEmailMessage(from, to, m)
	if err != nil {
		return 0, Permanent(err)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := emailDial(ctx, addr, host, implicitTLS)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// STARTTLS: upgrade if the peer supports it. Credentials must not be sent over a plain-text session (see the auth note below).
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return 0, fmt.Errorf("STARTTLS failed: %w", err)
			}
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			// smtp.PlainAuth refuses to send credentials over an unencrypted connection (unless the target is localhost).
			// This is the **correct** security behaviour and must not be bypassed, but the reason needs to be explained clearly;
			// otherwise users would only see "unencrypted connection" without knowing what to do.
			if strings.Contains(err.Error(), "unencrypted connection") {
				return 0, Permanent(fmt.Errorf("refusing to send credentials: the connection is not encrypted. Enable TLS, switch to port 465 (implicit TLS), or tick \"Enable TLS\" (%w)", err))
			}
			return 0, Permanent(fmt.Errorf("SMTP authentication failed: %w", err))
		}
	}
	if err := client.Mail(from); err != nil {
		return 0, smtpStageError(fmt.Sprintf("sender %s was rejected", from), err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return 0, smtpStageError(fmt.Sprintf("recipient %s was rejected", rcpt), err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("SMTP DATA failed: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return 0, fmt.Errorf("failed to write email body: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("failed to submit email: %w", err)
	}
	// A failed Quit does not change the fact that "the server has accepted the email", so its error is ignored.
	_ = client.Quit()
	// Email has no length truncation (the whole HTML body is sent), so the whole batch counts as delivered.
	return len(m.Items), nil
}

// emailDial establishes the SMTP connection.
//
// implicitTLS=true uses the "TLS on connect" style such as port 465; false connects in plain text on 25/587 and then
// upgrades with STARTTLS. The two cannot be mixed: sending a plain-text greeting to port 465 gets the connection dropped immediately.
//
// The session deadline is set **at connection time** (not added afterwards), because net/smtp's Client hides the underlying
// connection in an unexported field that cannot be reached from outside; once the connection is handed over, only a deadline set in advance
// can act as the backstop. This also covers blocking during the handshake.
// Control hooks in blockInternalDial, sharing the same guard as the HTTP-based channels. Without it SMTP
// would be the gap in the whole SSRF protection: a host of 169.254.169.254 or 127.0.0.1 could be connected to directly,
// and when the smtp.NewClient handshake fails it wraps the line returned by the peer into the error, which via last_error
// is echoed by the delivery history endpoint, forming a semi-blind read primitive; the timing difference between "connection refused" and "timeout" could also
// be used to probe ports. The dial stage is where it finally takes effect, and it also covers DNS rebinding.
func emailDial(ctx context.Context, addr, host string, implicitTLS bool) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: emailDialTimeout, Control: blockInternalDial}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP handshake failed: %w", err)
	}
	return client, nil
}

// smtpStageError classifies a failure at some stage as "retryable" or "permanent" according to the SMTP reply code.
//
// Why the distinction is essential: SMTP 4xx and 5xx mean completely different things:
//   - 4xx (450 greylisting, 451 local error, 452 insufficient storage) are **temporary** rejections,
//     and the proper response is to retry later; greylisting in particular is met on almost every first delivery.
//   - 5xx (550 user does not exist, 553 invalid address) are permanent rejections where retrying is pointless.
//
// If everything were judged permanent, a mail server with greylisting enabled would put **every** notification into failed after the first
// attempt, and this kind of failure is exactly where automatic retries are most useful.
// The reply code is the first three digits of the error text; when no code can be found it is treated as retryable (better to try once more
// than to write off a possibly transient fault just because it could not be parsed).
func smtpStageError(what string, err error) error {
	code := smtpReplyCode(err.Error())
	if code >= 500 && code < 600 {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	return fmt.Errorf("%s: %w", what, err)
}

// smtpReplyCode takes the leading three-digit reply code from an SMTP error text, returning 0 when there is none.
// net/smtp does not export an error code field, so it can only be taken from the text; the format is "450 4.7.1 ...".
func smtpReplyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	n, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return n
}

// buildEmailMessage assembles the complete RFC 5322 email.
//
// The body is base64-encoded for two reasons: first, SMTP limits a single line to 1000 bytes, and HTML
// bodies (especially digest emails) easily have overlong lines; second, base64 never produces lines starting with ".",
// which avoids the bother of SMTP dot-stuffing.
func buildEmailMessage(from string, to []string, m Message) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	// Non-ASCII subjects must be RFC 2047 encoded, otherwise clients display them as garbled text.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", htmlTitle(m)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	// Email has no hard length limit, so the body is not truncated.
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody(m, 0)))
	// base64 wraps at 76 characters, in line with RFC 2045.
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String(), nil
}
