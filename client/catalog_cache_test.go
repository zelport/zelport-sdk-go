package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zelport/zelport-sdk-go/protocol"
	"github.com/zelport/zelport-sdk-go/secure"
)

func TestCatalogHintsPreserveAuthenticationAndExpiry(t *testing.T) {
	secret := bytes.Repeat([]byte{6}, 32)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	fail := false
	c, err := New(Options{GroupToken: secret, Identity: protocol.Identity{ID: protocol.ID(), PrivateKey: key.Bytes()}, Registry: &registry{}, AcceptRecord: func(protocol.Record, []byte) error {
		if fail {
			return io.ErrClosedPipe
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	now := time.Now().Unix()
	record := protocol.Record{Version: 3, Group: c.group, DeviceID: protocol.ID(), Hostname: "provider", PublicKey: protocol.RandomNonce(), Sequence: 1, IssuedAt: now, ExpiresAt: now + 60, Port: 8080}
	raw, err := secure.SealCatalog(record, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.accept(raw); err != nil {
		t.Fatal(err)
	}
	route, _ := secure.CatalogRouteID(secret, record.DeviceID)
	if c.knownCatalog()[route] != protocol.Digest(raw) {
		t.Fatal("accepted envelope not cached")
	}
	fail = true
	record.Sequence++
	newer, _ := secure.SealCatalog(record, secret)
	if err = c.accept(newer); err == nil {
		t.Fatal("persistence failure ignored")
	}
	if c.knownCatalog()[route] != protocol.Digest(raw) {
		t.Fatal("unpersisted envelope advertised")
	}
	foreign, _ := secure.SealCatalog(record, bytes.Repeat([]byte{9}, 32))
	if err = c.accept(foreign); err == nil {
		t.Fatal("forged envelope accepted")
	}
	if c.knownCatalog()[route] != protocol.Digest(raw) {
		t.Fatal("rejected envelope advertised")
	}

	// A malicious relay may omit every record, but an empty successful response
	// must not be treated as proof that a provider or its catalog remains fresh.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctl := &control{conn: a, pending: map[string]chan protocol.Message{}, done: make(chan struct{})}
	defer ctl.close()
	go c.readControl(ctl)
	done := make(chan error, 1)
	go func() {
		var request protocol.Message
		err := protocol.ReadJSON(b, &request)
		if err == nil {
			err = protocol.WriteJSON(b, protocol.Message{Type: "result", ID: request.ID})
		}
		done <- err
	}()
	if err = c.catalog(ctl); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if got := c.Snapshot().Records[0]; got.Sequence != 1 || got.ExpiresAt != now+60 {
		t.Fatal("relay omission changed freshness")
	}
	c.mu.Lock()
	expired := c.records[record.DeviceID]
	expired.record.ExpiresAt = now - 1
	c.records[record.DeviceID] = expired
	c.mu.Unlock()
	if len(c.knownCatalog()) != 0 {
		t.Fatal("expired record advertised as known")
	}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	if _, err = c.lookup(protocol.Import{Group: c.group, DeviceID: record.DeviceID, ProviderKey: record.PublicKey, ServiceID: protocol.ID()}); err == nil {
		t.Fatal("expired provider remained usable")
	}
}
