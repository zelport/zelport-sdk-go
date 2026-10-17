package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Record struct {
	Version   int       `json:"version"`
	Group     string    `json:"group"`
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname"`
	PublicKey string    `json:"public_key"`
	Sequence  uint64    `json:"sequence"`
	IssuedAt  int64     `json:"issued_at"`
	ExpiresAt int64     `json:"expires_at"`
	Port      int       `json:"port"`
	Publish   bool      `json:"publish"`
	Services  []Service `json:"services"`
}

func (r Record) validate() error {
	if r.Version != Version || len(r.Group) != 64 || strings.Trim(r.Group, "0123456789abcdef") != "" || !ValidID(r.DeviceID) || r.Sequence == 0 || r.Port < 1 || r.Port > 65535 || len(r.Hostname) > 253 || r.Hostname == "" || len(r.Services) > MaxServices || r.ExpiresAt-r.IssuedAt != 60 {
		return errors.New("invalid catalog record")
	}
	if _, e := DecodeKey(r.PublicKey); e != nil {
		return e
	}
	admins := 0
	ids, names := map[string]bool{}, map[string]bool{}
	for _, s := range r.Services {
		if !ValidID(s.ID) || !ValidDomain(s.Domain) || ids[s.ID] || names[s.Domain] {
			return errors.New("invalid or duplicate catalog service")
		}
		switch s.Kind {
		case Administration:
			admins++
			if admins > 1 || s.Domain != r.DeviceID+".zelport.localhost" {
				return errors.New("invalid administration service")
			}
		case Application:
			if ReservedDomain(s.Domain) || !r.Publish {
				return errors.New("invalid application publication")
			}
		default:
			return errors.New("unknown service kind")
		}
		ids[s.ID] = true
		names[s.Domain] = true
	}

	return nil
}
func canonicalRecord(r Record) ([]byte, error) {
	if e := r.validate(); e != nil {
		return nil, e
	}
	r.Services = append([]Service{}, r.Services...)
	sort.Slice(r.Services, func(i, j int) bool { return r.Services[i].ID < r.Services[j].ID })
	pairs := make([][3]string, len(r.Services))
	for i, s := range r.Services {
		pairs[i] = [3]string{s.ID, s.Domain, s.Kind}
	}
	b, e := json.Marshal([]any{r.Version, r.Group, r.DeviceID, r.Hostname, r.PublicKey, r.Sequence, r.IssuedAt, r.ExpiresAt, r.Port, r.Publish, pairs})
	if e != nil {
		return nil, e
	}
	return b, nil
}
func CanonicalRecord(r Record) ([]byte, error) { return canonicalRecord(r) }
func ParseCanonicalRecord(b []byte, now time.Time) (Record, error) {
	r, e := parseRecord(b)
	if e != nil {
		return r, e
	}
	canonical, e := CanonicalRecord(r)
	if e != nil {
		return r, e
	}
	if !bytes.Equal(b, canonical) {
		return r, errors.New("noncanonical catalog record")
	}
	if r.IssuedAt > now.Unix()+5 || r.ExpiresAt <= now.Unix() {
		return r, errors.New("catalog expired or clock skew exceeded")
	}
	return r, nil
}
func sign(b, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid authentication key")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return json.Marshal([2]string{base64.RawURLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(mac.Sum(nil))})
}
func payload(encoded, key []byte) ([]byte, error) {
	var parts [2]string
	var fields []string
	if len(encoded) > MaxControl {
		return nil, errors.New("record too large")
	}
	if e := Decode(encoded, &fields); e != nil || len(fields) != 2 {
		return nil, errors.New("invalid authentication envelope")
	}
	copy(parts[:], fields)
	b, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return nil, e
	}
	tag, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return nil, e
	}
	if key != nil {
		if len(key) != 32 {
			return nil, errors.New("invalid authentication key")
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(b)
		if !hmac.Equal(mac.Sum(nil), tag) {
			return nil, errors.New("catalog authentication failed")
		}
	}
	return b, nil
}

func parseRecord(b []byte) (Record, error) {
	var r Record
	var pairs [][]string
	e := Array(b, &r.Version, &r.Group, &r.DeviceID, &r.Hostname, &r.PublicKey, &r.Sequence, &r.IssuedAt, &r.ExpiresAt, &r.Port, &r.Publish, &pairs)
	if e != nil {
		return r, e
	}
	r.Services = []Service{}
	for _, p := range pairs {
		if len(p) != 3 {
			return r, errors.New("invalid service tuple")
		}
		r.Services = append(r.Services, Service{ID: p[0], Domain: p[1], Kind: p[2]})
	}
	return r, r.validate()
}
func Digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func (r Record) Authority(service string) (string, error) {

	for _, s := range r.Services {
		if s.ID == service && (r.Publish || s.Kind == Administration) {
			if r.Port == 80 {
				return s.Domain, nil
			}
			return fmt.Sprintf("%s:%d", s.Domain, r.Port), nil
		}
	}
	return "", errors.New("service unavailable")
}
