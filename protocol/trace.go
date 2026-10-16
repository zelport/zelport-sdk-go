package protocol

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type Trace struct {
	Group, Request      string
	Visits              [][2]string
	IssuedAt, ExpiresAt int64
}

// AdvanceTrace accepts the group token so the envelope carries the catalog locator.
func AdvanceTrace(encoded string, groupToken []byte, device, service string, now time.Time) (string, error) {
	if len(groupToken) != 32 || !ValidID(device) || !ValidID(service) {
		return "", errors.New("invalid trace context")
	}
	key, e := hkdf.Key(sha256.New, groupToken, []byte("snitzel-cloud/v1"), "trace-mac", 32)
	if e != nil {
		return "", e
	}
	locator, _ := hkdf.Key(sha256.New, groupToken, []byte("snitzel-cloud/v1"), "group-locator", 32)
	group := hex.EncodeToString(locator)
	v := Trace{Group: group, Request: ID(), Visits: [][2]string{}}
	if encoded != "" {
		if len(encoded) > 4096 {
			return "", errors.New("trace exceeds limit")
		}
		raw, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if e != nil {
			return "", errors.New("invalid trace")
		}
		raw, e = payload(raw, key)
		if e != nil {
			return "", e
		}
		var version int
		if e = Array(raw, &version, &v.Group, &v.Request, &v.Visits, &v.IssuedAt, &v.ExpiresAt); e != nil {
			return "", e
		}
		if version != Version || v.Group != group || !ValidID(v.Request) || v.ExpiresAt <= now.Unix() || v.IssuedAt > now.Unix()+5 || v.ExpiresAt-v.IssuedAt != 120 {
			return "", errors.New("invalid or expired trace")
		}
	}
	if len(v.Visits) >= 8 {
		return "", errors.New("cloud hop limit exceeded")
	}
	for _, pair := range v.Visits {
		if !ValidID(pair[0]) || !ValidID(pair[1]) || (pair[0] == device && pair[1] == service) {
			return "", errors.New("cloud loop detected")
		}
	}
	v.Visits = append(v.Visits, [2]string{device, service})
	v.IssuedAt = now.Unix()
	v.ExpiresAt = v.IssuedAt + 120
	b, e := json.Marshal([]any{Version, v.Group, v.Request, v.Visits, v.IssuedAt, v.ExpiresAt})
	if e != nil {
		return "", e
	}
	b, e = sign(b, key)
	if e != nil {
		return "", e
	}
	encoded = base64.RawURLEncoding.EncodeToString(b)
	if len(encoded) > 4096 {
		return "", errors.New("trace exceeds limit")
	}
	return encoded, nil
}
