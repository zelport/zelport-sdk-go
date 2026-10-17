package secure

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/flynn/noise"
	"github.com/zelport/zelport-sdk-go/protocol"
	"math"
	"time"
)

type renewalPolicy struct {
	softAge, hardAge, timeout   time.Duration
	softBytes, hardBytes, rekey uint64
}

func defaultRenewalPolicy() renewalPolicy {
	return renewalPolicy{10 * time.Minute, 15 * time.Minute, 10 * time.Second, 1 << 30, 2 << 30, 1048576}
}

const (
	active = iota
	waitHS2
	waitHS3
	waitConsumerFinish
	waitProviderFinish
	sendProviderFinish
)

func (c *peerConn) queueLocked(f peerFrame) error {
	if len(c.controls) >= 16 {
		return errors.New("peer control queue exceeded")
	}
	if _, e := f.bytes(); e != nil {
		return e
	}
	c.controls = append(c.controls, f)
	c.signalLocked()
	return nil
}
func (c *peerConn) internalDeadlineLocked() time.Time {
	d := c.born.Add(c.policy.hardAge)
	if !c.renewStarted.IsZero() {
		r := c.renewStarted.Add(c.policy.timeout)
		if r.Before(d) {
			d = r
		}
	}
	return d
}
func (c *peerConn) nextWakeLocked() time.Time {
	d := c.internalDeadlineLocked()
	if c.phase == active && !c.requested {
		soft := c.born.Add(c.policy.softAge)
		if soft.Before(d) {
			d = soft
		}
	}
	return d
}
func (c *peerConn) tickLocked() error {
	now := time.Now()
	if !now.Before(c.internalDeadlineLocked()) {
		return errors.New("peer key lifetime or renewal timeout exceeded")
	}
	if c.phase == active && !c.requested && (now.Sub(c.born) >= c.policy.softAge || c.txBytes >= c.policy.softBytes || c.rxBytes >= c.policy.softBytes) {
		if c.cfg.Initiator {
			return c.startRenewalLocked()
		}
		c.requested = true
		return c.queueLocked(peerFrame{peerRenewRequest, epochBytes(c.epoch)})
	}
	return nil
}
func (c *peerConn) newHandshakeLocked() error {
	if c.epoch == math.MaxUint64 {
		return errors.New("peer epoch exhausted")
	}
	cfg := c.cfg
	prologue := append([]byte(protocol.RenewalCryptoContext), c.cfg.Prologue...)
	prologue = append(prologue, c.original...)
	prologue = append(prologue, c.binding...)
	prologue = append(prologue, epochBytes(c.epoch+1)...)
	cfg.Prologue = prologue
	h, e := noise.NewHandshakeState(cfg)
	if e != nil {
		return e
	}
	c.handshake = h
	c.renewStarted = time.Now()
	return c.raw.SetReadDeadline(c.internalDeadlineLocked())
}
func (c *peerConn) startRenewalLocked() error {
	if c.phase != active {
		return nil
	}
	if e := c.newHandshakeLocked(); e != nil {
		return e
	}
	msg, _, _, e := c.handshake.WriteMessage(nil, nil)
	if e != nil {
		return e
	}
	c.phase = waitHS2
	return c.queueLocked(peerFrame{peerHS1, append(epochBytes(c.epoch+1), msg...)})
}
func (c *peerConn) handshakeMessageLocked(f peerFrame) ([]byte, error) {
	if len(f.body) < 8 || binary.BigEndian.Uint64(f.body[:8]) != c.epoch+1 {
		return nil, errors.New("unexpected peer epoch")
	}
	return f.body[8:], nil
}
func (c *peerConn) finishBodyLocked(initiator bool) []byte {
	role := byte(0)
	if initiator {
		role = 1
	}
	return append(append(epochBytes(c.epoch+1), role), c.nextBinding...)
}
func (c *peerConn) installLocked(a, b *noise.CipherState) error {
	if a == nil || b == nil || !bytes.Equal(c.expected, c.handshake.PeerStatic()) {
		return errors.New("renewal identity mismatch")
	}
	if !c.cfg.Initiator {
		a, b = b, a
	}
	c.nextTX = a
	c.rx = b
	c.reads = 0
	c.rxBytes = 0
	c.nextBinding = append([]byte(nil), c.handshake.ChannelBinding()...)
	return nil
}
func (c *peerConn) completeLocked() error {
	c.epoch++
	c.binding = c.nextBinding
	c.nextBinding = nil
	c.handshake = nil
	c.phase = active
	c.born = time.Now()
	c.renewStarted = time.Time{}
	c.requested = false
	return c.raw.SetReadDeadline(c.internalDeadlineLocked())
}
func (c *peerConn) controlLocked(f peerFrame) error {
	if f.kind == peerRenewRequest {
		if !c.cfg.Initiator || len(f.body) != 8 || binary.BigEndian.Uint64(f.body) != c.epoch || (c.phase != active && c.phase != waitHS2) {
			return errors.New("unexpected renewal request")
		}
		return c.startRenewalLocked()
	}
	body, e := c.handshakeMessageLocked(f)
	if e != nil {
		return e
	}
	switch f.kind {
	case peerHS1:
		if c.cfg.Initiator || c.phase != active {
			return errors.New("unexpected HS1")
		}
		if e = c.newHandshakeLocked(); e != nil {
			return e
		}
		payload, _, _, err := c.handshake.ReadMessage(nil, body)
		if err != nil {
			return err
		}
		if len(payload) != 0 {
			return errors.New("unexpected handshake payload")
		}
		msg, _, _, err := c.handshake.WriteMessage(nil, nil)
		if err != nil {
			return err
		}
		c.phase = waitHS3
		return c.queueLocked(peerFrame{peerHS2, append(epochBytes(c.epoch+1), msg...)})
	case peerHS2:
		if !c.cfg.Initiator || c.phase != waitHS2 {
			return errors.New("unexpected HS2")
		}
		payload, _, _, err := c.handshake.ReadMessage(nil, body)
		if err != nil {
			return err
		}
		if len(payload) != 0 {
			return errors.New("unexpected handshake payload")
		}
		msg, a, b, err := c.handshake.WriteMessage(nil, nil)
		if err != nil {
			return err
		}
		if err = c.installLocked(a, b); err != nil {
			return err
		}
		c.phase = waitProviderFinish
		return c.queueLocked(peerFrame{peerHS3, append(epochBytes(c.epoch+1), msg...)})
	case peerHS3:
		if c.cfg.Initiator || c.phase != waitHS3 {
			return errors.New("unexpected HS3")
		}
		payload, a, b, err := c.handshake.ReadMessage(nil, body)
		if err != nil {
			return err
		}
		if len(payload) != 0 {
			return errors.New("unexpected handshake payload")
		}
		if err = c.installLocked(a, b); err != nil {
			return err
		}
		c.phase = waitConsumerFinish
		return nil
	case peerFinish:
		if c.phase != waitConsumerFinish && c.phase != waitProviderFinish {
			return errors.New("unexpected FINISH")
		}
		if !bytes.Equal(f.body, c.finishBodyLocked(!c.cfg.Initiator)) {
			return errors.New("invalid renewal confirmation")
		}
		if c.cfg.Initiator {
			return c.completeLocked()
		}
		c.tx = c.nextTX
		c.nextTX = nil
		c.writes = 0
		c.txBytes = 0
		c.phase = sendProviderFinish
		return c.queueLocked(peerFrame{peerFinish, c.finishBodyLocked(false)})
	default:
		return errors.New("unexpected renewal control")
	}
}
func (c *peerConn) afterWriteLocked(f peerFrame) error {
	if f.kind == peerHS3 {
		if !c.cfg.Initiator || c.phase != waitProviderFinish || c.nextTX == nil {
			return errors.New("invalid outgoing HS3 transition")
		}
		c.tx = c.nextTX
		c.nextTX = nil
		c.writes = 0
		c.txBytes = 0
		return c.queueLocked(peerFrame{peerFinish, c.finishBodyLocked(true)})
	}
	if f.kind == peerFinish && !c.cfg.Initiator {
		if c.phase != sendProviderFinish {
			return errors.New("invalid outgoing FINISH transition")
		}
		return c.completeLocked()
	}
	return nil
}
