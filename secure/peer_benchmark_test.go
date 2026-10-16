package secure

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"net"
	"testing"
	"time"
)

func benchmarkPair(b *testing.B) (*peerConn, *peerConn) {
	b.Helper()
	priv1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	priv2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	i := protocol.Identity{ID: protocol.ID(), PrivateKey: priv1.Bytes()}
	p := protocol.Identity{ID: protocol.ID(), PrivateKey: priv2.Bytes()}
	peer := protocol.PeerContext{Version: 3, Group: string(bytes.Repeat([]byte("a"), 64)), Consumer: i.ID, Provider: p.ID, ConsumerKey: base64.RawURLEncoding.EncodeToString(priv1.PublicKey().Bytes()), ProviderKey: base64.RawURLEncoding.EncodeToString(priv2.PublicKey().Bytes()), Session: protocol.RandomNonce()}
	secret := bytes.Repeat([]byte{9}, 32)
	route, _ := PeerRoute(secret, peer)
	a, z := net.Pipe()
	ch := make(chan *peerConn, 1)
	errch := make(chan error, 1)
	go func() {
		c, e := peerWithOptions(context.Background(), z, false, p, secret, peer, route, peerOptions{})
		if e != nil {
			errch <- e
			return
		}
		ch <- c.(*peerConn)
	}()
	c, e := peerWithOptions(context.Background(), a, true, i, secret, peer, route, peerOptions{})
	if e != nil {
		b.Fatal(e)
	}
	select {
	case d := <-ch:
		return c.(*peerConn), d
	case e := <-errch:
		b.Fatal(e)
	}
	return nil, nil
}
func BenchmarkPeerHandshake(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		a, c := benchmarkPair(b)
		a.Close()
		c.Close()
	}
}
func BenchmarkPeerRenewal(b *testing.B) {
	a, c := benchmarkPair(b)
	defer a.Close()
	defer c.Close()
	b.ReportAllocs()
	b.ResetTimer()
	var maxPause time.Duration
	for range b.N {
		start := time.Now()
		a.mu.Lock()
		epoch := a.epoch
		if e := a.startRenewalLocked(); e != nil {
			b.Fatal(e)
		}
		a.mu.Unlock()
		for {
			a.mu.Lock()
			done, e, ch := a.epoch > epoch, a.err, a.changed
			a.mu.Unlock()
			if e != nil {
				b.Fatal(e)
			}
			if done {
				break
			}
			<-ch
		}
		maxPause = max(maxPause, time.Since(start))
	}
	b.ReportMetric(float64(maxPause.Nanoseconds()), "max-pause-ns")
}
func BenchmarkPeerThroughput(b *testing.B) {
	a, c := benchmarkPair(b)
	defer a.Close()
	defer c.Close()
	payload := make([]byte, 256<<10)
	done := make(chan error, 1)
	go func() { _, e := io.CopyN(io.Discard, c, int64(len(payload))*int64(b.N)); done <- e }()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, e := a.Write(payload); e != nil {
			b.Fatal(e)
		}
	}
	if e := <-done; e != nil {
		b.Fatal(e)
	}
}
