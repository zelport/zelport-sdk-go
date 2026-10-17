package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"github.com/hashicorp/yamux"
	"github.com/zelport/zelport-sdk-go/protocol"
	"github.com/zelport/zelport-sdk-go/secure"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type registry struct {
	mu      sync.Mutex
	record  protocol.Record
	enabled bool
}

func (r *registry) Catalog(context.Context) (protocol.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.record.Sequence++
	r.record.IssuedAt = time.Now().Unix()
	r.record.ExpiresAt = r.record.IssuedAt + 60
	return r.record, nil
}

func (r *registry) Open(ctx context.Context, peer protocol.PeerContext, o protocol.OpenRequest) (net.Conn, error) {
	r.mu.Lock()
	enabled := r.enabled
	r.mu.Unlock()
	if !enabled {
		return nil, io.ErrClosedPipe
	}
	a, b := net.Pipe()
	go func() { defer b.Close(); io.Copy(b, b) }()
	return a, nil
}

func TestCatalogPersistenceFailurePreservesTrust(t *testing.T) {
	secret := bytes.Repeat([]byte{6}, 32)
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var fail bool
	c, e := New(Options{GroupToken: secret, Identity: protocol.Identity{ID: protocol.ID(), PrivateKey: priv.Bytes()}, Registry: &registry{}, AcceptRecord: func(protocol.Record, []byte) error {
		if fail {
			return io.ErrClosedPipe
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	r := protocol.Record{Version: 1, Group: c.group, DeviceID: protocol.ID(), Hostname: "original", PublicKey: protocol.RandomNonce(), Sequence: 1, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 60, Port: 8080}
	a, e := secure.SealCatalog(r, secret)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.accept(a); e != nil {
		t.Fatal(e)
	}
	fail = true
	r.Sequence++
	r.Hostname = "unpersisted"
	b, _ := secure.SealCatalog(r, secret)
	if e = c.accept(b); e == nil {
		t.Fatal("persistence failure ignored")
	}
	if got := c.Snapshot().Records[0]; got.Sequence != 1 || got.Hostname != "original" {
		t.Fatal("unpersisted trust exposed", got)
	}
	fail = false
	r.PublicKey = protocol.RandomNonce()
	b, _ = secure.SealCatalog(r, secret)
	if e = c.accept(b); e == nil {
		t.Fatal("identity substitution accepted")
	}
}

func TestCatalogConcurrentAcceptance(t *testing.T) {
	secret := bytes.Repeat([]byte{6}, 32)
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	entered, release := make(chan struct{}), make(chan struct{})
	c, e := New(Options{GroupToken: secret, Identity: protocol.Identity{ID: protocol.ID(), PrivateKey: priv.Bytes()}, Registry: &registry{}, AcceptRecord: func(r protocol.Record, _ []byte) error {
		if r.Sequence == 2 {
			close(entered)
			<-release
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	r := protocol.Record{Version: 1, Group: c.group, DeviceID: protocol.ID(), Hostname: "host", PublicKey: protocol.RandomNonce(), Sequence: 2, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 60, Port: 8080}
	low, _ := secure.SealCatalog(r, secret)
	r.Sequence = 3
	high, _ := secure.SealCatalog(r, secret)
	done := make(chan error, 2)
	go func() { done <- c.accept(low) }()
	<-entered
	go func() { done <- c.accept(high) }()
	close(release)
	for range 2 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	if c.Snapshot().Records[0].Sequence != 3 {
		t.Fatal("delayed acceptance rolled back cache")
	}
	same, _ := secure.SealCatalog(r, secret)
	if bytes.Equal(same, high) {
		t.Fatal("nonce reuse")
	}
	if e := c.accept(same); e != nil {
		t.Fatal("random nonce broke idempotence", e)
	}
}

type lockOnClose struct {
	net.Conn
	mu *sync.Mutex
}

func (c lockOnClose) Close() error { c.mu.Lock(); c.mu.Unlock(); return c.Conn.Close() }

func TestEstablishShutdownClosesOutsideClientLock(t *testing.T) {
	c := &Client{closed: true, dialing: map[string]chan struct{}{"key": make(chan struct{})}}
	a, b := net.Pipe()
	defer b.Close()
	mux, e := yamux.Client(lockOnClose{a, &c.mu}, muxConfig())
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := c.finishEstablish("key", &session{mux: mux}, nil); done <- e }()
	select {
	case e := <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("session close holds client mutex needed by authorization")
	}
}
