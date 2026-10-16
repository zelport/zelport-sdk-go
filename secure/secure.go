// Package secure implements independently authenticated relay and peer channels.
package secure

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/flynn/noise"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"net"
	"sync"
	"time"
)

func Derive(secret []byte, purpose string) ([32]byte, error) {
	var key [32]byte
	if len(secret) != 32 {
		return key, errors.New("invalid secret length")
	}
	switch purpose {
	case "group-locator", "catalog-mac", "peer-psk", "trace-mac", "relay-admission":
	default:
		return key, errors.New("unknown key purpose")
	}
	b, e := hkdf.Key(sha256.New, secret, []byte("snitzel-cloud/v1"), purpose, 32)
	copy(key[:], b)
	return key, e
}
func Public(private []byte) ([]byte, error) {
	k, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, e
	}
	return k.PublicKey().Bytes(), nil
}

const admissionMaxPlain = 32768
const admissionTagSize = 16

type Conn struct {
	deadlineMu    sync.Mutex
	writeDeadline time.Time
	net.Conn
	readHeader                       [4]byte
	readFrame, readPlain, writeFrame []byte
	readMu, writeMu                  sync.Mutex
	rx, tx                           *noise.CipherState
	pending                          []byte
	reads, writes, rekey             uint64
	Hello                            protocol.Hello
	binding                          []byte
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return c.Conn.SetDeadline(t)
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return c.Conn.SetWriteDeadline(t)
}
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) == 0 {
		// Validate the advertised size before allocating or growing storage.
		if _, e := io.ReadFull(c.Conn, c.readHeader[:]); e != nil {
			c.Close()
			return 0, e
		}
		size := binary.BigEndian.Uint32(c.readHeader[:])
		if size < admissionTagSize+1 || size > admissionMaxPlain+admissionTagSize {
			c.Close()
			return 0, errors.New("invalid encrypted record length")
		}
		c.readFrame = admissionBuffer(c.readFrame, int(size))
		if _, e := io.ReadFull(c.Conn, c.readFrame); e != nil {
			c.Close()
			return 0, e
		}

		c.reads++
		if c.reads%c.rekey == 0 {
			c.rx.Rekey()
		}
		c.readPlain = admissionBuffer(c.readPlain, int(size)-admissionTagSize)
		plain, e := c.rx.Decrypt(c.readPlain[:0], nil, c.readFrame)
		c.pending = plain
		if e != nil {
			c.Close()
			return 0, errors.New("record authentication failed")
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		c.deadlineMu.Lock()
		deadline := time.Now().Add(30 * time.Second)
		if !c.writeDeadline.IsZero() && c.writeDeadline.Before(deadline) {
			deadline = c.writeDeadline
		}
		c.Conn.SetWriteDeadline(deadline)
		c.deadlineMu.Unlock()
		n := len(p)
		if n > admissionMaxPlain {
			n = admissionMaxPlain
		}
		c.writes++
		if c.writes%c.rekey == 0 {
			c.tx.Rekey()
		}
		// Prefix space lets one transport write carry the complete record.
		c.writeFrame = admissionBuffer(c.writeFrame, 4+n+admissionTagSize)
		b, e := c.tx.Encrypt(c.writeFrame[:4], nil, p[:n])
		if e == nil {
			binary.BigEndian.PutUint32(b[:4], uint32(len(b)-4))
			e = writeAdmissionRecord(c.Conn, b)
		}
		if e != nil {
			c.Close()
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func Admit(ctx context.Context, c net.Conn, initiator bool, token []byte, hello protocol.Hello) (result net.Conn, err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	c.SetDeadline(deadline)
	var raw []byte
	if initiator {
		raw, err = hello.Bytes()
		if err == nil {
			err = protocol.WriteFrame(c, raw, 2048)
		}
	} else {
		raw, err = protocol.ReadFrame(c, 2048)
		if err == nil {
			hello, err = protocol.ParseHello(raw)
		}
	}
	if err != nil {
		return nil, err
	}
	// Empty admission tokens explicitly select Noise NN, without relay authentication.
	// The distinct prologue prevents interpreting protected handshakes as open ones.
	cfg := noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: noise.HandshakeNN, Initiator: initiator, Prologue: append([]byte("snitzel-cloud/v3/client-relay/"), raw...)}
	if len(token) == 0 {
		cfg.Prologue = append([]byte("snitzel-cloud/v3/client-relay/open/"), raw...)
	} else {
		key, e := Derive(token, "relay-admission")
		if e != nil {
			return nil, e
		}
		cfg.PresharedKey = key[:]
		cfg.PresharedKeyPlacement = 2
	}
	secure, err := handshake(c, cfg, 2, nil)
	if err != nil {
		return nil, err
	}
	secure.Hello = hello
	secure.SetDeadline(deadline)
	if err = ready(secure, initiator); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	secure.SetDeadline(time.Time{})
	return secure, nil
}
func handshake(c net.Conn, cfg noise.Config, messages int, expected []byte) (*Conn, error) {
	h, e := noise.NewHandshakeState(cfg)
	if e != nil {
		return nil, e
	}
	var tx, rx *noise.CipherState
	for i := 0; i < messages; i++ {
		var a, b *noise.CipherState
		var data []byte
		if (i%2 == 0) == cfg.Initiator {
			data, a, b, e = h.WriteMessage(nil, nil)
			if e == nil {
				e = protocol.WriteFrame(c, data, 4096)
			}
		} else {
			data, e = protocol.ReadFrame(c, 4096)
			if e == nil {
				var payload []byte
				payload, a, b, e = h.ReadMessage(nil, data)
				if e == nil && len(payload) != 0 {
					e = errors.New("unexpected handshake payload")
				}
			}
		}
		if e != nil {
			return nil, e
		}
		if a != nil {
			tx, rx = a, b
		}
	}
	if expected != nil && !bytes.Equal(expected, h.PeerStatic()) {
		return nil, errors.New("peer identity mismatch")
	}
	if !cfg.Initiator {
		tx, rx = rx, tx
	}
	return &Conn{Conn: c, tx: tx, rx: rx, rekey: 1048576, binding: append([]byte(nil), h.ChannelBinding()...)}, nil
}
func ready(c net.Conn, initiator bool) error {
	read := func() error {
		var b [5]byte
		_, e := io.ReadFull(c, b[:])
		if e == nil && string(b[:]) != "ready" {
			return errors.New("confirmation failed")
		}
		return e
	}
	write := func() error { _, e := c.Write([]byte("ready")); return e }
	if initiator {
		if e := write(); e != nil {
			return e
		}
		return read()
	}
	if e := read(); e != nil {
		return e
	}
	return write()
}

// writeAdmissionRecord preserves stream writer semantics without splitting the
// length prefix from its ciphertext on transports that accept a complete write.
func writeAdmissionRecord(w io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// Storage grows on demand to the largest validated record on this connection.
// Read and write storage never alias; pending plaintext is drained before reuse.
func admissionBuffer(buf []byte, size int) []byte {
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}
