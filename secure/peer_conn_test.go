package secure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func peerPair(t *testing.T, options peerOptions) (*peerConn, *peerConn) {
	a, b := net.Pipe()
	return peerPairCarrier(t, options, a, b)
}
func peerPairCarrier(t *testing.T, options peerOptions, a, b net.Conn) (*peerConn, *peerConn) {
	return peerPairContext(t, context.Background(), options, a, b)
}
func peerPairContext(t *testing.T, ctx context.Context, options peerOptions, a, b net.Conn) (*peerConn, *peerConn) {
	t.Helper()
	i, ik := identity(t)
	p, pk := identity(t)
	secret := bytes.Repeat([]byte{9}, 32)
	peer := protocol.PeerContext{Version: 3, Group: string(bytes.Repeat([]byte("a"), 64)), Consumer: i.ID, Provider: p.ID, ConsumerKey: ik, ProviderKey: pk, Session: protocol.RandomNonce()}
	route := testPeerRoute(t, secret, peer)
	type result struct {
		c net.Conn
		e error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := peerWithOptions(ctx, b, false, p, secret, peer, route, options)
		ch <- result{c, e}
	}()
	ca, e := peerWithOptions(ctx, a, true, i, secret, peer, route, options)
	if e != nil {
		t.Fatal(e)
	}
	rb := <-ch
	if rb.e != nil {
		t.Fatal(rb.e)
	}
	x, y := ca.(*peerConn), rb.c.(*peerConn)
	t.Cleanup(func() { x.Close(); y.Close() })
	return x, y
}
func TestPeerCreditWindow(t *testing.T) {
	a, b := peerPair(t, peerOptions{})
	payload := bytes.Repeat([]byte("a"), 512<<10)
	done := make(chan error, 1)
	go func() { _, e := a.Write(payload); done <- e }()
	select {
	case e := <-done:
		t.Fatal("write exceeded unread window", e)
	case <-time.After(30 * time.Millisecond):
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(b, got); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil || !bytes.Equal(payload, got) {
		t.Fatal("stream corruption", e)
	}
}
func TestPeerDeadlinesAndClose(t *testing.T) {
	a, b := peerPair(t, peerOptions{})
	a.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e := a.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	a.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, e := a.Write(make([]byte, 1<<20)); done <- e }()
	b.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("closed write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake writer")
	}
}
func TestPeerSaturatedDuplex(t *testing.T) {
	a, b := peerPair(t, peerOptions{})
	payload := bytes.Repeat([]byte("duplex"), 100000)
	done := make(chan error, 4)
	for _, c := range []*peerConn{a, b} {
		go func() { _, e := c.Write(payload); done <- e }()
		go func() {
			got := make([]byte, len(payload))
			_, e := io.ReadFull(c, got)
			if e == nil && !bytes.Equal(got, payload) {
				e = errors.New("corruption")
			}
			done <- e
		}()
	}
	for range 4 {
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("duplex deadlock")
		}
	}
}

type shortConn struct{ net.Conn }

func (c shortConn) Write(p []byte) (int, error) { return c.Conn.Write(p[:min(97, len(p))]) }
func (c shortConn) Read(p []byte) (int, error)  { return c.Conn.Read(p[:min(53, len(p))]) }
func TestPeerCarrierIndependence(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	a, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	b := <-ch
	if b == nil {
		t.Fatal("accept failed")
	}
	policy := defaultRenewalPolicy()
	policy.softBytes = 65536
	x, y := peerPairCarrier(t, peerOptions{policy: policy}, shortConn{a}, shortConn{b})
	payload := bytes.Repeat([]byte("tcp"), 100000)
	done := make(chan error, 1)
	go func() { _, e := x.Write(payload); done <- e }()
	got := make([]byte, len(payload))
	y.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, e := io.ReadFull(y, got); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil || !bytes.Equal(got, payload) {
		t.Fatal("carrier changed byte stream", e)
	}
}
func TestPeerPartialWrite(t *testing.T) {
	a, _ := peerPair(t, peerOptions{})
	a.SetWriteDeadline(time.Now().Add(40 * time.Millisecond))
	n, e := a.Write(make([]byte, 2*peerWindow))
	if !errors.Is(e, os.ErrDeadlineExceeded) || n != peerWindow {
		t.Fatal("partial credit-limited write", n, e)
	}
}
func TestPeerResourceQuiescence(t *testing.T) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	workers := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			policy := defaultRenewalPolicy()
			policy.softBytes = 65536
			a, b := peerPair(t, peerOptions{policy: policy})
			done := make(chan error, 1)
			go func() { _, e := a.Write(make([]byte, 1<<20)); done <- e }()
			if _, e := io.CopyN(io.Discard, b, 1<<20); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			a.Close()
			b.Close()
		})
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("quiescent live heap delta=%d bytes; goroutines before=%d after=%d", growth, workers, runtime.NumGoroutine())
	if growth > 8<<20 {
		t.Fatal("retained heap grew after closed peer cycles")
	}
	if runtime.NumGoroutine() > workers+4 {
		t.Fatal("peer workers retained")
	}
}
