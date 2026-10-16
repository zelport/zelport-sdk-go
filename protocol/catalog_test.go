package protocol

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func record() Record {
	return Record{Version: Version, Group: string(bytes.Repeat([]byte("a"), 64)), DeviceID: ID(), Hostname: "laptop", PublicKey: RandomNonce(), Sequence: 1, IssuedAt: 1000, ExpiresAt: 1060, Port: 8080, Publish: true, Services: []Service{{Kind: Application, ID: ID(), Domain: "demo.localhost"}}}
}
func TestCatalogForgeryAndExpiry(t *testing.T) {
	r := record()
	b, e := CanonicalRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseCanonicalRecord(b, time.Unix(1030, 0)); e != nil {
		t.Fatal(e)
	}
	if _, e = ParseCanonicalRecord(b, time.Unix(1061, 0)); e == nil {
		t.Fatal("expired accepted")
	}
	if _, e = ParseCanonicalRecord(b, time.Unix(994, 0)); e == nil {
		t.Fatal("future accepted")
	}
	r.Services = append(r.Services, r.Services[0])
	if _, e = CanonicalRecord(r); e == nil {
		t.Fatal("duplicate service")
	}
}
func TestTraceLoopsAndBounds(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 32)
	now := time.Unix(1000, 0)
	device, service := ID(), ID()
	trace, e := AdvanceTrace("", key, device, service, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = AdvanceTrace(trace, key, device, service, now); e == nil {
		t.Fatal("loop allowed")
	}
	for range 7 {
		trace, e = AdvanceTrace(trace, key, ID(), ID(), now)
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, e = AdvanceTrace(trace, key, ID(), ID(), now); e == nil {
		t.Fatal("ninth allowed")
	}
	if _, e = AdvanceTrace(trace, key, ID(), ID(), now.Add(3*time.Minute)); e == nil {
		t.Fatal("expired accepted")
	}
	if _, e = AdvanceTrace("forged", key, ID(), ID(), now); e == nil {
		t.Fatal("forged accepted")
	}
}
func TestWireBounds(t *testing.T) {
	for _, b := range [][]byte{{0, 0, 0, 0}, {255, 255, 255, 255}, {0, 0, 0, 2, 1}} {
		if _, e := ReadFrame(bytes.NewReader(b), 64); e == nil {
			t.Fatal("bad frame accepted")
		}
	}
	for _, b := range []string{`{"id":1,"id":2}`, `{} {}`, `null`} {
		var v any
		if Decode([]byte(b), &v) == nil {
			t.Fatal("invalid JSON", b)
		}
	}
}

func TestMaximumCatalogFitsControlFrame(t *testing.T) {
	r := record()
	r.Services = nil
	for i := 0; i < MaxServices; i++ {
		r.Services = append(r.Services, Service{Kind: Application, ID: ID(), Domain: fmt.Sprintf("%03d", i) + strings.Repeat("a", 60) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 51) + ".localhost"})
	}
	raw, e := CanonicalRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	var frame bytes.Buffer
	if e = WriteJSON(&frame, Message{Type: "register", ID: ID(), Record: raw}); e != nil {
		t.Fatal(e)
	}
	var got Message
	if e = ReadJSON(&frame, &got); e != nil || !bytes.Equal(got.Record, raw) {
		t.Fatal("catalog roundtrip", e)
	}
}

func FuzzStrictWire(f *testing.F) {
	f.Add([]byte(`{"type":"catalog","id":"x"}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxControl {
			return
		}
		var m Message
		_ = Decode(b, &m)
		_, _ = ReadFrame(bytes.NewReader(b), MaxControl)
	})
}
func FuzzAuthenticatedCatalog(f *testing.F) {
	f.Add([]byte(`[]`))
	raw, _ := CanonicalRecord(record())
	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxControl {
			return
		}
		_, _ = ParseCanonicalRecord(b, time.Unix(1030, 0))
	})
}
