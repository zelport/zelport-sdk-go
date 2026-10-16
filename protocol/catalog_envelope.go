package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type CatalogEnvelope struct {
	Version           int
	Group, RouteID    string
	Nonce, Ciphertext []byte
}

func ValidLocator(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
func EncodeCatalogEnvelope(e CatalogEnvelope) ([]byte, error) {
	if e.Version != 3 || !ValidLocator(e.Group) || !ValidLocator(e.RouteID) || len(e.Nonce) != 24 || len(e.Ciphertext) < 16 {
		return nil, errors.New("invalid catalog envelope")
	}
	b, err := json.Marshal([]any{e.Version, e.Group, e.RouteID, base64.RawURLEncoding.EncodeToString(e.Nonce), base64.RawURLEncoding.EncodeToString(e.Ciphertext)})
	if len(b) > MaxControl {
		return nil, errors.New("catalog envelope too large")
	}
	return b, err
}
func ParseCatalogEnvelope(b []byte) (CatalogEnvelope, error) {
	var e CatalogEnvelope
	var nonce, ciphertext string
	if len(b) > MaxControl {
		return e, errors.New("catalog envelope too large")
	}
	if err := Array(b, &e.Version, &e.Group, &e.RouteID, &nonce, &ciphertext); err != nil {
		return e, err
	}
	var err error
	e.Nonce, err = base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil {
		return e, err
	}
	e.Ciphertext, err = base64.RawURLEncoding.Strict().DecodeString(ciphertext)
	if err != nil {
		return e, err
	}
	canonical, err := EncodeCatalogEnvelope(e)
	if err == nil && !bytes.Equal(canonical, b) {
		err = errors.New("noncanonical catalog envelope")
	}
	return e, err
}
