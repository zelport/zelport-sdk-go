package secure

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/zelport/zelport-sdk-go/protocol"
	"testing"
	"time"
)

func catalogFixture() (protocol.Record, []byte) {
	secret := bytes.Repeat([]byte{7}, 32)
	group, _ := Derive(secret, "group-locator")
	return protocol.Record{Version: 1, Group: hex.EncodeToString(group[:]), DeviceID: "11111111-1111-4111-8111-111111111111", Hostname: "private-host", PublicKey: protocol.RandomNonce(), Sequence: 1, IssuedAt: 1000, ExpiresAt: 1060, Port: 8080, Publish: true, Services: []protocol.Service{{ID: "22222222-2222-4222-8222-222222222222", Domain: "private.localhost", Kind: protocol.Application}}}, secret
}
func TestCatalogEnvelopeRoundTrip(t *testing.T) {
	r, s := catalogFixture()
	b, e := SealCatalog(r, s)
	if e != nil {
		t.Fatal(e)
	}
	got, plain, e := OpenCatalog(b, s, time.Unix(1030, 0))
	if e != nil || got.DeviceID != r.DeviceID || got.Services[0] != r.Services[0] {
		t.Fatalf("roundtrip: %+v %v", got, e)
	}
	if !bytes.Contains(plain, []byte(r.Hostname)) {
		t.Fatal("missing plaintext")
	}
	for _, private := range []string{r.DeviceID, r.Hostname, r.PublicKey, r.Services[0].Domain, r.Services[0].ID} {
		if bytes.Contains(b, []byte(private)) {
			t.Fatal("metadata leaked")
		}
	}
	for _, now := range []int64{994, 1060} {
		if _, _, e := OpenCatalog(b, s, time.Unix(now, 0)); e == nil {
			t.Fatal("invalid lifetime accepted")
		}
	}
}
func TestCatalogRandomizedSemanticIdentity(t *testing.T) {
	r, s := catalogFixture()
	a, e := SealCatalog(r, s)
	if e != nil {
		t.Fatal(e)
	}
	b, e := SealCatalog(r, s)
	if e != nil {
		t.Fatal(e)
	}
	_, pa, e := OpenCatalog(a, s, time.Unix(1030, 0))
	if e != nil {
		t.Fatal(e)
	}
	_, pb, e := OpenCatalog(b, s, time.Unix(1030, 0))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(a, b) || !bytes.Equal(pa, pb) {
		t.Fatal("nonce or semantic identity incorrect")
	}
}
func TestCatalogEnvelopeTamper(t *testing.T) {
	r, s := catalogFixture()
	b, _ := SealCatalog(r, s)
	if _, _, e := OpenCatalog(b, bytes.Repeat([]byte{8}, 32), time.Unix(1030, 0)); e == nil {
		t.Fatal("wrong secret")
	}
	for _, field := range []string{"group", "route", "nonce", "ciphertext"} {
		t.Run(field, func(t *testing.T) {
			env, e := protocol.ParseCatalogEnvelope(b)
			if e != nil {
				t.Fatal(e)
			}
			switch field {
			case "group":
				env.Group = string(bytes.Repeat([]byte("b"), 64))
			case "route":
				env.RouteID = string(bytes.Repeat([]byte("c"), 64))
			case "nonce":
				env.Nonce[0] ^= 1
			case "ciphertext":
				env.Ciphertext[0] ^= 1
			}
			bad, _ := protocol.EncodeCatalogEnvelope(env)
			if _, _, e := OpenCatalog(bad, s, time.Unix(1030, 0)); e == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}
func TestCatalogRoutingBinding(t *testing.T) {
	r, s := catalogFixture()
	a, e := CatalogRouteID(s, r.DeviceID)
	if e != nil {
		t.Fatal(e)
	}
	r.DeviceID = protocol.ID()
	b, _ := CatalogRouteID(s, r.DeviceID)
	if a != "022800b2d51ebf605c906ba340c82816b3a5c8df6dbb4bb289d49dfebf52dbc1" {
		t.Fatal("routing derivation vector changed", a)
	}
	if a == b || len(a) != 64 {
		t.Fatal("routing collision")
	}
	r.Group = string(bytes.Repeat([]byte("b"), 64))
	if _, e := SealCatalog(r, s); e == nil {
		t.Fatal("wrong group")
	}
}

type brokenRandom struct{}

func (brokenRandom) Read([]byte) (int, error) { return 0, errors.New("random unavailable") }
func TestCatalogBounds(t *testing.T) {
	r, s := catalogFixture()
	if _, e := sealCatalog(r, s, brokenRandom{}); e == nil {
		t.Fatal("random failure ignored")
	}
	r.Services = make([]protocol.Service, 257)
	if _, e := SealCatalog(r, s); e == nil {
		t.Fatal("oversized services")
	}
	if _, e := protocol.ParseCatalogEnvelope(bytes.Repeat([]byte("x"), protocol.MaxControl+1)); e == nil {
		t.Fatal("oversized envelope")
	}
}
