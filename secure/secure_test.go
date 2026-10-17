package secure

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func pair(t *testing.T, wrong bool) (net.Conn, net.Conn, error) {
	t.Helper()
	a, b := net.Pipe()
	token := bytes.Repeat([]byte{7}, 32)
	other := append([]byte(nil), token...)
	if wrong {
		other[0]++
	}
	type result struct {
		c net.Conn
		e error
	}
	ch := make(chan result, 1)
	go func() { c, e := Admit(context.Background(), b, false, other, protocol.Hello{}); ch <- result{c, e} }()
	c, e := Admit(context.Background(), a, true, token, protocol.NewHello("control"))
	r := <-ch
	if e != nil {
		return nil, nil, e
	}
	if r.e != nil {
		return nil, nil, r.e
	}
	return c, r.c, nil
}
func TestAdmissionWrongToken(t *testing.T) {
	if a, b, e := pair(t, true); e == nil {
		a.Close()
		b.Close()
		t.Fatal("wrong token admitted")
	}
}
func TestRekeyBidirectional(t *testing.T) {
	a, b, e := pair(t, false)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	defer b.Close()
	a.(*Conn).rekey = 3
	b.(*Conn).rekey = 3
	done := make(chan error, 1)
	go func() {
		for range 10 {
			if _, e := a.Write([]byte("hello")); e != nil {
				done <- e
				return
			}
			p := make([]byte, 5)
			if _, e := io.ReadFull(a, p); e != nil {
				done <- e
				return
			}
			if string(p) != "world" {
				done <- io.ErrUnexpectedEOF
				return
			}
		}
		done <- nil
	}()
	for range 10 {
		p := make([]byte, 5)
		if _, e := io.ReadFull(b, p); e != nil {
			t.Fatal(e)
		}
		if string(p) != "hello" {
			t.Fatal(string(p))
		}
		if _, e := b.Write([]byte("world")); e != nil {
			t.Fatal(e)
		}
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func identity(t *testing.T) (protocol.Identity, string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return protocol.Identity{ID: protocol.ID(), PrivateKey: k.Bytes()}, base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}
func TestPeerIdentityBinding(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "substitution"}[bad], func(t *testing.T) {
			i, ik := identity(t)
			p, pk := identity(t)
			contextValue := protocol.PeerContext{Version: protocol.Version, Group: string(bytes.Repeat([]byte("a"), 64)), Consumer: i.ID, Provider: p.ID, ConsumerKey: ik, ProviderKey: pk, Session: protocol.RandomNonce()}
			if bad {
				_, contextValue.ProviderKey = identity(t)
			}
			a, b := net.Pipe()
			ch := make(chan error, 1)
			go func() {
				c, e := Peer(context.Background(), b, false, p, bytes.Repeat([]byte{8}, 32), contextValue, testPeerRoute(t, bytes.Repeat([]byte{8}, 32), contextValue), PeerOptions{})
				if c != nil {
					c.Close()
				}
				ch <- e
			}()
			c, e := Peer(context.Background(), a, true, i, bytes.Repeat([]byte{8}, 32), contextValue, testPeerRoute(t, bytes.Repeat([]byte{8}, 32), contextValue), PeerOptions{})
			if c != nil {
				c.Close()
			}
			other := <-ch
			if bad && (e == nil || other == nil) {
				t.Fatal("substituted identity accepted")
			}
			if !bad && (e != nil || other != nil) {
				t.Fatal(e, other)
			}
		})
	}
}
func TestHandshakeCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, e := Admit(ctx, a, true, bytes.Repeat([]byte{1}, 32), protocol.NewHello("control")); e == nil {
		t.Fatal("cancel accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation stalled")
	}
}
func TestKDFPurposeSeparation(t *testing.T) {
	s := bytes.Repeat([]byte{1}, 32)
	a, e := Derive(s, "catalog-mac")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := Derive(s, "peer-psk")
	if a == b {
		t.Fatal("keys reused")
	}
	if _, e = Derive(s, "unknown"); e == nil {
		t.Fatal("unknown purpose")
	}
}

type captureConn struct {
	net.Conn
	mu      sync.Mutex
	capture bytes.Buffer
	tamper  bool
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.capture.Write(p)
	out := append([]byte(nil), p...)
	if c.tamper && len(out) > 4 {
		out[len(out)-1] ^= 1
	}
	c.mu.Unlock()
	return c.Conn.Write(out)
}
func TestCiphertextTamperReplayAndSecretCapture(t *testing.T) {
	for _, attack := range []string{"tamper", "replay"} {
		t.Run(attack, func(t *testing.T) {
			a, b := net.Pipe()
			wire := &captureConn{Conn: a}
			token := bytes.Repeat([]byte{17}, 32)
			result := make(chan net.Conn, 1)
			go func() {
				c, e := Admit(context.Background(), b, false, token, protocol.Hello{})
				if e != nil {
					result <- nil
				} else {
					result <- c
				}
			}()
			sender, e := Admit(context.Background(), wire, true, token, protocol.NewHello("control"))
			if e != nil {
				t.Fatal(e)
			}
			receiver := <-result
			if receiver == nil {
				t.Fatal("admission failed")
			}
			defer sender.Close()
			defer receiver.Close()
			wire.mu.Lock()
			captured := append([]byte(nil), wire.capture.Bytes()...)
			wire.capture.Reset()
			wire.tamper = attack == "tamper"
			wire.mu.Unlock()
			if bytes.Contains(captured, token) {
				t.Fatal("admission exposed token")
			}
			done := make(chan error, 1)
			go func() { _, e := sender.Write([]byte("private-application-content")); done <- e }()
			buf := make([]byte, 100)
			n, e := receiver.Read(buf)
			<-done
			if attack == "tamper" {
				if e == nil {
					t.Fatal("tamper accepted")
				}
				return
			}
			if e != nil || string(buf[:n]) != "private-application-content" {
				t.Fatal(e)
			}
			wire.mu.Lock()
			frame := append([]byte(nil), wire.capture.Bytes()...)
			wire.mu.Unlock()
			if bytes.Contains(frame, []byte("private-application-content")) {
				t.Fatal("plaintext in capture")
			}
			go func() { _, e := wire.Conn.Write(frame); done <- e }()
			if _, e = receiver.Read(buf); e == nil {
				t.Fatal("replayed ciphertext accepted")
			}
			<-done
		})
	}
}

func TestKDFVectors(t *testing.T) {
	vectors := map[string]string{"group-locator": "b8ab1144ae020acfd510ad9c4f96bba3ad5388ee8ab02cca37cead2021e10ad1", "catalog-mac": "bb4a62dc15a7931211340ac566f504e116aff2250dac37cb24d54d9ce6727779", "peer-psk": "8c083550386a43e2f02ed60fb1279252f9df781f5639a9bf7fecc3196344aa0b", "trace-mac": "c2fc0d56d16d8928cd02ceefc7739a3f87e10eaa7e81b4e2d8e1f2ca22e3648a", "relay-admission": "8d327374a9b7903d50b12f3f3cdc29f9bc3d2047114f421adedcaa2dd3e706d3"}
	for purpose, want := range vectors {
		key, e := Derive(bytes.Repeat([]byte{1}, 32), purpose)
		if e != nil || hex.EncodeToString(key[:]) != want {
			t.Fatal(purpose, e)
		}
	}
}

func TestEncryptedWriteHonorsDeadline(t *testing.T) {
	a, b, e := pair(t, false)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	defer b.Close()
	a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	start := time.Now()
	if _, e = a.Write([]byte("blocked")); e == nil {
		t.Fatal("write unexpectedly completed")
	}
	if time.Since(start) > time.Second {
		t.Fatal("write deadline ignored")
	}
}

func TestAdmissionRecordedHelloAndReadyCannotBeReplayed(t *testing.T) {
	a, b := net.Pipe()
	wire := &captureConn{Conn: a}
	token := bytes.Repeat([]byte{19}, 32)
	result := make(chan net.Conn, 1)
	go func() {
		c, e := Admit(context.Background(), b, false, token, protocol.Hello{})
		if e != nil {
			result <- nil
		} else {
			result <- c
		}
	}()
	original, e := Admit(context.Background(), wire, true, token, protocol.NewHello("control"))
	if e != nil {
		t.Fatal(e)
	}
	receiver := <-result
	if receiver == nil {
		t.Fatal("original failed")
	}
	wire.mu.Lock()
	capture := append([]byte(nil), wire.capture.Bytes()...)
	wire.mu.Unlock()
	original.Close()
	receiver.Close()
	x, y := net.Pipe()
	defer x.Close()
	defer y.Close()
	x.SetDeadline(time.Now().Add(time.Second))
	replayResult := make(chan error, 1)
	go func() {
		c, e := Admit(context.Background(), y, false, token, protocol.Hello{})
		if c != nil {
			c.Close()
		}
		replayResult <- e
	}()
	frames := bytes.NewReader(capture)
	for range 2 {
		frame, e := protocol.ReadFrame(frames, 4096)
		if e != nil {
			t.Fatal(e)
		}
		if e = protocol.WriteFrame(x, frame, 4096); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = protocol.ReadFrame(x, 4096); e != nil {
		t.Fatal(e)
	}
	readyFrame, e := protocol.ReadFrame(frames, 4096)
	if e != nil {
		t.Fatal(e)
	}
	_ = protocol.WriteFrame(x, readyFrame, 4096)
	if e = <-replayResult; e == nil {
		t.Fatal("captured admission authorized replay")
	}
}
func TestPeerContextSubstitutionAndDowngrade(t *testing.T) {
	for _, field := range []string{"group", "consumer", "provider", "session", "version", "token"} {
		t.Run(field, func(t *testing.T) {
			i, ik := identity(t)
			p, pk := identity(t)
			expected := protocol.PeerContext{Version: protocol.Version, Group: string(bytes.Repeat([]byte("a"), 64)), Consumer: i.ID, Provider: p.ID, ConsumerKey: ik, ProviderKey: pk, Session: protocol.RandomNonce()}
			changed := expected
			token := bytes.Repeat([]byte{8}, 32)
			otherToken := append([]byte(nil), token...)
			switch field {
			case "group":
				changed.Group = string(bytes.Repeat([]byte("b"), 64))
			case "consumer":
				changed.Consumer = protocol.ID()
			case "provider":
				changed.Provider = protocol.ID()
			case "session":
				changed.Session = protocol.RandomNonce()
			case "version":
				changed.Version = 0
			case "token":
				otherToken[0]++
			}
			a, b := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ch := make(chan error, 1)
			go func() {
				c, e := Peer(ctx, b, false, p, otherToken, changed, testPeerRoute(t, otherToken, changed), PeerOptions{})
				if c != nil {
					c.Close()
				}
				ch <- e
			}()
			c, e := Peer(ctx, a, true, i, token, expected, testPeerRoute(t, token, expected), PeerOptions{})
			if c != nil {
				c.Close()
			}
			other := <-ch
			if e == nil || other == nil {
				t.Fatal("altered context authenticated", field, e, other)
			}
		})
	}
}

func TestAdmissionOpenModeAndNoDowngrade(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		name           string
		client, server []byte
		ok             bool
	}{
		{"open", nil, nil, true}, {"protected", key, key, true}, {"empty_client", nil, key, false}, {"token_client", key, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			type result struct {
				c net.Conn
				e error
			}
			ch := make(chan result, 1)
			go func() { c, e := Admit(ctx, b, false, tc.server, protocol.Hello{}); ch <- result{c, e} }()
			c, e := Admit(ctx, a, true, tc.client, protocol.NewHello("control"))
			r := <-ch
			if c != nil {
				defer c.Close()
			}
			if r.c != nil {
				defer r.c.Close()
			}
			if tc.ok != (e == nil && r.e == nil) {
				t.Fatalf("client=%v server=%v", e, r.e)
			}
			if tc.ok {
				done := make(chan error, 1)
				go func() { _, e := c.Write([]byte("encrypted")); done <- e }()
				v := make([]byte, 9)
				if _, e := io.ReadFull(r.c, v); e != nil || string(v) != "encrypted" {
					t.Fatal(e)
				}
				if e := <-done; e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func testPeerRoute(t *testing.T, secret []byte, p protocol.PeerContext) protocol.RelayRoute {
	t.Helper()
	r, e := PeerRoute(secret, p)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
