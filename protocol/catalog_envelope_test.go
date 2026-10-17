package protocol

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCatalogEnvelopeStrictness(t *testing.T) {
	e := CatalogEnvelope{Version: 1, Group: string(bytes.Repeat([]byte("a"), 64)), RouteID: string(bytes.Repeat([]byte("b"), 64)), Nonce: make([]byte, 24), Ciphertext: make([]byte, 16)}
	b, err := EncodeCatalogEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append([]byte(" "), b...), bytes.Replace(b, []byte("[1,"), []byte("[2,"), 1), bytes.Replace(b, []byte("[1,"), []byte("[1,0,"), 1), bytes.Replace(b, []byte(`"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`), []byte(`"AA=="`), 1)} {
		if _, err := ParseCatalogEnvelope(bad); err == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
}
func TestCatalogCanonicalOrdering(t *testing.T) {
	r := record()
	r.Services = append(r.Services, Service{ID: ID(), Domain: "other.localhost", Kind: Application})
	a, e := CanonicalRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	r.Services[0], r.Services[1] = r.Services[1], r.Services[0]
	b, e := CanonicalRecord(r)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("service ordering changed digest", e)
	}
	if _, e := ParseCanonicalRecord(append([]byte(" "), a...), time.Unix(1030, 0)); e == nil {
		t.Fatal("noncanonical plaintext accepted")
	}
}

func TestCatalogCompleteMessageBounds(t *testing.T) {
	m := Message{Type: "result", Error: strings.Repeat("x", MaxControl-len(`{"type":"result","error":""}`))}
	var b bytes.Buffer
	if e := WriteJSON(&b, m); e != nil || b.Len() != MaxControl+4 {
		t.Fatal("exact full-message bound", b.Len(), e)
	}
	b.Reset()
	m.Error += "x"
	if e := WriteJSON(&b, m); e == nil || b.Len() != 0 {
		t.Fatal("oversized message partially sent", e)
	}
	env := CatalogEnvelope{Version: 1, Group: strings.Repeat("a", 64), RouteID: strings.Repeat("b", 64), Nonce: make([]byte, 24), Ciphertext: make([]byte, 98000)}
	raw, e := EncodeCatalogEnvelope(env)
	if e != nil {
		t.Fatal(e)
	}
	m = Message{Type: "register", ID: ID(), Record: raw}
	if _, e = EncodeMessage(m); e != nil {
		t.Fatal(e)
	}
	for n := 98001; n < MaxControl; n++ {
		env.Ciphertext = make([]byte, n)
		raw, e = EncodeCatalogEnvelope(env)
		if e != nil {
			t.Fatal("envelope rejected before outer overhead tested")
		}
		m.Record = raw
		if _, e = EncodeMessage(m); e != nil {
			return
		}
	}
	t.Fatal("outer message limit not enforced")
}
