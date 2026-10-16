package secure

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/zelport/zelport-sdk-go/protocol"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"time"
)

func catalogKey(secret []byte, purpose string) ([]byte, error) {
	if len(secret) != 32 {
		return nil, errors.New("invalid E2E secret")
	}
	return hkdf.Key(sha256.New, secret, []byte("snitzel-cloud/v3"), purpose, 32)
}
func CatalogRouteID(secret []byte, deviceID string) (string, error) {
	if !protocol.ValidID(deviceID) {
		return "", errors.New("invalid device identity")
	}
	key, e := catalogKey(secret, "catalog-routing")
	if e != nil {
		return "", e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(deviceID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
func catalogParameters(secret []byte, e protocol.CatalogEnvelope) ([]byte, []byte, error) {
	info, _ := json.Marshal([]any{"catalog-encryption", e.Group, e.RouteID})
	key, err := catalogKey(secret, string(info))
	ad, _ := json.Marshal([]any{"snitzel-cloud/v3/catalog", 3, e.Group, e.RouteID})
	return key, ad, err
}
func SealCatalog(r protocol.Record, secret []byte) ([]byte, error) {
	return sealCatalog(r, secret, rand.Reader)
}
func sealCatalog(r protocol.Record, secret []byte, random io.Reader) ([]byte, error) {
	plain, err := protocol.CanonicalRecord(r)
	if err != nil {
		return nil, err
	}
	group, err := Derive(secret, "group-locator")
	if err != nil {
		return nil, err
	}
	if r.Group != hex.EncodeToString(group[:]) {
		return nil, errors.New("catalog group mismatch")
	}
	route, err := CatalogRouteID(secret, r.DeviceID)
	if err != nil {
		return nil, err
	}
	e := protocol.CatalogEnvelope{Version: 3, Group: r.Group, RouteID: route, Nonce: make([]byte, 24)}
	if _, err = io.ReadFull(random, e.Nonce); err != nil {
		return nil, err
	}
	key, ad, err := catalogParameters(secret, e)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	payload, err := encodeCatalogPayload(plain)
	if err != nil {
		return nil, err
	}
	e.Ciphertext = aead.Seal(nil, e.Nonce, payload, ad)
	return protocol.EncodeCatalogEnvelope(e)
}
func OpenCatalog(raw, secret []byte, now time.Time) (protocol.Record, []byte, error) {
	var r protocol.Record
	e, err := protocol.ParseCatalogEnvelope(raw)
	if err != nil {
		return r, nil, err
	}
	group, err := Derive(secret, "group-locator")
	if err != nil {
		return r, nil, err
	}
	if e.Group != hex.EncodeToString(group[:]) {
		return r, nil, errors.New("catalog group mismatch")
	}
	key, ad, err := catalogParameters(secret, e)
	if err != nil {
		return r, nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return r, nil, err
	}
	plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, ad)
	if err != nil {
		return r, nil, errors.New("catalog authentication failed")
	}
	plain, err = decodeCatalogPayload(plain)
	if err != nil {
		return r, nil, err
	}
	r, err = protocol.ParseCanonicalRecord(plain, now)
	if err != nil {
		return r, nil, err
	}
	route, err := CatalogRouteID(secret, r.DeviceID)
	if err != nil {
		return r, nil, err
	}
	if r.Group != e.Group || route != e.RouteID {
		return r, nil, errors.New("catalog routing mismatch")
	}
	return r, plain, nil
}
