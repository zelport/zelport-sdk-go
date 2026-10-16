package secure

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/flynn/noise"
	"github.com/zelport/zelport-sdk-go/protocol"
	"net"
	"os"
	"sync"
	"time"
)

type PeerOptions struct {
	Authorize func(protocol.PeerContext) error
}
type peerOptions struct {
	PeerOptions
	policy renewalPolicy
}
type peerWrite struct {
	data []byte
	sent int
	done bool
}

// peerConn owns one record reader and one record writer. Application backpressure
// consumes credit, never the record reader, so control messages can always progress.
type peerConn struct {
	cfg                                      noise.Config
	expected, original, binding, nextBinding []byte
	nextTX                                   *noise.CipherState
	handshake                                *noise.HandshakeState
	epoch, txBytes, rxBytes                  uint64
	phase                                    int
	born, renewStarted                       time.Time
	requested                                bool
	policy                                   renewalPolicy
	peer                                     protocol.PeerContext
	raw                                      net.Conn
	mu                                       sync.Mutex
	writeMu                                  sync.Mutex
	deadlineMu                               sync.Mutex
	changed                                  chan struct{}
	done                                     chan struct{}
	wg                                       sync.WaitGroup
	stop                                     func() bool
	err                                      error
	rx, tx                                   *noise.CipherState
	reads, writes                            uint64
	recv                                     bytes.Buffer
	sendCredit, recvCredit, pendingCredit    int
	controls                                 []peerFrame
	request                                  *peerWrite
	readDeadline, writeDeadline              time.Time
	options                                  peerOptions
}

func newPeerConn(ctx context.Context, raw net.Conn, tx, rx *noise.CipherState, options peerOptions, cfg noise.Config, binding, expected []byte, peer protocol.PeerContext) *peerConn {
	policy := options.policy
	if policy.softAge == 0 {
		policy = defaultRenewalPolicy()
	}
	c := &peerConn{reads: 1, writes: 1, txBytes: 42, rxBytes: 42, cfg: cfg, binding: append([]byte(nil), binding...), original: append([]byte(nil), binding...), expected: append([]byte(nil), expected...), peer: peer, policy: policy, born: time.Now(), raw: raw, tx: tx, rx: rx, changed: make(chan struct{}), done: make(chan struct{}), sendCredit: peerWindow, recvCredit: peerWindow, options: options}
	c.raw.SetReadDeadline(c.internalDeadlineLocked())
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()
	c.stop = context.AfterFunc(ctx, func() { c.fail(ctx.Err()) })
	return c
}
func (c *peerConn) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *peerConn) fail(e error) {
	c.mu.Lock()
	if c.err == nil {
		if e == nil {
			e = net.ErrClosed
		}
		c.err = e
		c.request = nil
		close(c.done)
		c.signalLocked()
	}
	c.mu.Unlock()
	c.raw.Close()
}
func (c *peerConn) Close() error {
	c.fail(net.ErrClosed)
	if c.stop != nil {
		c.stop()
	}
	c.wg.Wait()
	return nil
}
func (c *peerConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *peerConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }
func (c *peerConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *peerConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.mu.Lock()
	c.writeDeadline = t
	c.signalLocked()
	internal := c.internalDeadlineLocked()
	c.mu.Unlock()
	if t.IsZero() || internal.Before(t) {
		t = internal
	}
	return c.raw.SetWriteDeadline(t)
}
func (c *peerConn) SetDeadline(t time.Time) error { c.SetReadDeadline(t); return c.SetWriteDeadline(t) }
func waitPeer(ch <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		<-ch
		return nil
	}
	left := time.Until(deadline)
	if left <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(left)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}
func (c *peerConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if c.recv.Len() > 0 {
			n, _ := c.recv.Read(p)
			c.pendingCredit += n
			c.signalLocked()
			return n, nil
		}
		if c.err != nil {
			return 0, c.err
		}
		ch, deadline := c.changed, c.readDeadline
		c.mu.Unlock()
		e := waitPeer(ch, deadline)
		c.mu.Lock()
		if e != nil {
			return 0, e
		}
	}
}
func (c *peerConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.err != nil {
		e := c.err
		c.mu.Unlock()
		return 0, e
	}
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	req := &peerWrite{data: p}
	c.request = req
	c.signalLocked()
	for {
		if req.done || c.err != nil {
			n, e := req.sent, c.err
			c.mu.Unlock()
			return n, e
		}
		ch, deadline := c.changed, c.writeDeadline
		c.mu.Unlock()
		e := waitPeer(ch, deadline)
		c.mu.Lock()
		if e != nil {
			n := req.sent
			c.mu.Unlock()
			c.fail(e)
			return n, e
		}
	}
}
func (c *peerConn) nextLocked() (peerFrame, *peerWrite, int) {
	if len(c.controls) > 0 {
		f := c.controls[0]
		c.controls = c.controls[1:]
		return f, nil, 0
	}
	if c.phase != active {
		return peerFrame{}, nil, 0
	}
	if c.pendingCredit > 0 {
		n := c.pendingCredit
		c.pendingCredit = 0
		c.recvCredit += n
		return peerFrame{peerCredit, binary.BigEndian.AppendUint32(nil, uint32(n))}, nil, 0
	}
	if r := c.request; r != nil && c.sendCredit > 0 {
		n := min(len(r.data)-r.sent, c.sendCredit, peerMaxPlain-1)
		if n > 0 {
			c.sendCredit -= n
			return peerFrame{peerData, append([]byte(nil), r.data[r.sent:r.sent+n]...)}, r, n
		}
	}
	return peerFrame{}, nil, 0
}
func (c *peerConn) writeLoop() {
	defer c.wg.Done()
	for {
		c.mu.Lock()
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		if e := c.tickLocked(); e != nil {
			c.mu.Unlock()
			c.fail(e)
			return
		}
		f, req, n := c.nextLocked()
		if f.kind == 0 {
			ch := c.changed
			deadline := c.nextWakeLocked()
			c.mu.Unlock()
			_ = waitPeer(ch, deadline)
			continue
		}
		plain, e := f.bytes()
		c.txBytes += uint64(len(plain))
		if c.txBytes > c.policy.hardBytes {
			e = errors.New("peer transmit key budget exceeded")
		}
		c.writes++
		if c.writes%c.policy.rekey == 0 {
			c.tx.Rekey()
		}
		var encrypted []byte
		if e == nil {
			encrypted, e = c.tx.Encrypt(nil, nil, plain)
		}
		c.mu.Unlock()
		if e == nil {
			c.deadlineMu.Lock()
			c.mu.Lock()
			deadline := time.Now().Add(30 * time.Second)
			if internal := c.internalDeadlineLocked(); internal.Before(deadline) {
				deadline = internal
			}
			if !c.writeDeadline.IsZero() && c.writeDeadline.Before(deadline) {
				deadline = c.writeDeadline
			}
			c.mu.Unlock()
			c.raw.SetWriteDeadline(deadline)
			c.deadlineMu.Unlock()
			e = protocol.WriteFrame(c.raw, encrypted, peerMaxPlain+16)
		}
		if e != nil {
			c.fail(e)
			return
		}
		c.mu.Lock()
		if req != nil {
			req.sent += n
			if req.sent == len(req.data) {
				req.done = true
				c.request = nil
			}
		}
		e = c.afterWriteLocked(f)
		c.signalLocked()
		c.mu.Unlock()
		if e != nil {
			c.fail(e)
			return
		}
	}
}
func (c *peerConn) readLoop() {
	defer c.wg.Done()
	for {
		raw, e := protocol.ReadFrame(c.raw, peerMaxPlain+16)
		if e != nil {
			c.fail(e)
			return
		}
		c.mu.Lock()
		c.reads++
		if c.reads%c.policy.rekey == 0 {
			c.rx.Rekey()
		}
		for c.phase == sendProviderFinish && c.err == nil {
			ch := c.changed
			c.mu.Unlock()
			<-ch
			c.mu.Lock()
		}
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		if !time.Now().Before(c.internalDeadlineLocked()) {
			c.mu.Unlock()
			c.fail(errors.New("peer key lifetime exceeded"))
			return
		}
		plain, e := c.rx.Decrypt(nil, nil, raw)
		c.rxBytes += uint64(len(plain))
		if c.rxBytes > c.policy.hardBytes {
			e = errors.New("peer receive key budget exceeded")
		}
		if e == nil {
			var f peerFrame
			f, e = parsePeerFrame(plain)
			if e == nil {
				if f.kind >= peerHS1 && c.options.Authorize != nil {
					c.mu.Unlock()
					e = c.options.Authorize(c.peer)
					c.mu.Lock()
				}
				if e == nil {
					e = c.receiveLocked(f)
				}
			}
		}
		c.signalLocked()
		c.mu.Unlock()
		if e != nil {
			c.fail(e)
			return
		}
	}
}
func (c *peerConn) receiveLocked(f peerFrame) error {
	if (f.kind == peerData || f.kind == peerCredit) && c.phase != active && c.phase != waitHS2 {
		return errors.New("data after renewal barrier")
	}
	switch f.kind {
	case peerData:
		if len(f.body) == 0 || len(f.body) > c.recvCredit {
			return errors.New("peer receive credit exceeded")
		}
		c.recvCredit -= len(f.body)
		_, e := c.recv.Write(f.body)
		return e
	case peerCredit:
		if len(f.body) != 4 {
			return errors.New("invalid peer credit")
		}
		n := int(binary.BigEndian.Uint32(f.body))
		if n == 0 || n > peerWindow-c.sendCredit {
			return errors.New("peer credit overflow")
		}
		c.sendCredit += n
		return nil
	default:
		return c.controlLocked(f)
	}
}

var _ net.Conn = (*peerConn)(nil)
