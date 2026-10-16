package protocol

import (
	"bytes"
	"testing"
)

func TestV3OpaquePairing(t *testing.T) {
	r := RelayRoute{Version: 3, Group: string(bytes.Repeat([]byte("a"), 64)), ConsumerRoute: string(bytes.Repeat([]byte("b"), 64)), ProviderRoute: string(bytes.Repeat([]byte("c"), 64)), Session: RandomNonce()}
	b, e := r.Bytes()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseRelayRoute(b)
	if e != nil || got != r {
		t.Fatal(got, e)
	}
	r.Version = 2
	if _, e := r.Bytes(); e == nil {
		t.Fatal("v2 accepted")
	}
}
func TestV3RejectsV2(t *testing.T) {
	h := NewHello("control")
	h.Version = 2
	if _, e := h.Bytes(); e == nil {
		t.Fatal("v2 hello accepted")
	}
}

func TestPairingWireIsFixedArray(t *testing.T) {
	r := RelayRoute{Version: 3, Group: string(bytes.Repeat([]byte("a"), 64)), ConsumerRoute: string(bytes.Repeat([]byte("b"), 64)), ProviderRoute: string(bytes.Repeat([]byte("c"), 64)), Session: RandomNonce()}
	var b bytes.Buffer
	if e := WriteJSON(&b, Message{Type: "connect", Route: &r}); e != nil {
		t.Fatal(e)
	}
	raw, e := ReadFrame(&b, MaxControl)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(raw, []byte(`"route":[3,`)) {
		t.Fatalf("route is not a fixed array: %s", raw)
	}
	var m Message
	if e = Decode(raw, &m); e != nil || m.Route == nil || *m.Route != r {
		t.Fatal("route roundtrip", e)
	}
}
