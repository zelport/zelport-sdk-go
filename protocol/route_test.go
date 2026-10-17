package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestV1OpaquePairing(t *testing.T) {
	r := RelayRoute{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), ConsumerRoute: string(bytes.Repeat([]byte("b"), 64)), ProviderRoute: string(bytes.Repeat([]byte("c"), 64)), Session: RandomNonce()}
	b, e := r.Bytes()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseRelayRoute(b)
	if e != nil || got != r {
		t.Fatal(got, e)
	}
	for _, version := range []int{0, 2, 3} {
		r.Version = version
		if _, e := r.Bytes(); e == nil {
			t.Fatalf("version %d accepted", version)
		}
	}
}
func TestV1RejectsEveryOtherVersion(t *testing.T) {
	h := NewHello("control")
	if h.Version != 1 {
		t.Fatalf("hello version = %d, want 1", h.Version)
	}
	for _, version := range []int{0, 2, 3} {
		h.Version = version
		if _, e := h.Bytes(); e == nil {
			t.Fatalf("hello version %d accepted", version)
		}
	}
}

func TestPairingWireIsFixedArray(t *testing.T) {
	r := RelayRoute{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), ConsumerRoute: string(bytes.Repeat([]byte("b"), 64)), ProviderRoute: string(bytes.Repeat([]byte("c"), 64)), Session: RandomNonce()}
	var b bytes.Buffer
	if e := WriteJSON(&b, Message{Type: "connect", Route: &r}); e != nil {
		t.Fatal(e)
	}
	raw, e := ReadFrame(&b, MaxControl)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(raw, []byte(`"route":[1,`)) {
		t.Fatalf("route is not a fixed array: %s", raw)
	}
	var m Message
	if e = Decode(raw, &m); e != nil || m.Route == nil || *m.Route != r {
		t.Fatal("route roundtrip", e)
	}
}

func TestVersionedWireArraysStartWithOne(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	consumer, provider := ID(), ID()
	cases := map[string]func() ([]byte, error){
		"hello": func() ([]byte, error) {
			return (Hello{Version: 1, Purpose: "control", Nonce: key}).Bytes()
		},
		"peer context": func() ([]byte, error) {
			return (PeerContext{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), Consumer: consumer, Provider: provider, ConsumerKey: key, ProviderKey: key, Session: key}).Bytes()
		},
		"relay route": func() ([]byte, error) {
			return (RelayRoute{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), ConsumerRoute: string(bytes.Repeat([]byte("b"), 64)), ProviderRoute: string(bytes.Repeat([]byte("c"), 64)), Session: key}).Bytes()
		},
		"catalog record": func() ([]byte, error) {
			return CanonicalRecord(record())
		},
		"catalog envelope": func() ([]byte, error) {
			return EncodeCatalogEnvelope(CatalogEnvelope{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), RouteID: string(bytes.Repeat([]byte("b"), 64)), Nonce: make([]byte, 24), Ciphertext: make([]byte, 16)})
		},
	}
	for name, encode := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := encode()
			if err != nil {
				t.Fatal(err)
			}
			var fields []json.RawMessage
			if err = Decode(raw, &fields); err != nil || len(fields) == 0 || string(fields[0]) != "1" {
				t.Fatalf("wire value = %s, want array beginning with 1", raw)
			}
		})
	}
}
