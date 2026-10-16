package secure

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewalSaturatedDuplex(t *testing.T) {
	policy := defaultRenewalPolicy()
	policy.softBytes = 64 << 10
	policy.hardBytes = 2 << 20
	a, b := peerPair(t, peerOptions{policy: policy})
	payload := bytes.Repeat([]byte("renewal-payload"), 60000)
	done := make(chan error, 4)
	for _, c := range []*peerConn{a, b} {
		go func() { _, e := c.Write(payload); done <- e }()
		go func() {
			got := make([]byte, len(payload))
			_, e := io.ReadFull(c, got)
			if e == nil && !bytes.Equal(got, payload) {
				t.Error("corrupted stream")
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
			t.Fatal("renewal deadlock")
		}
	}
	a.mu.Lock()
	epoch := a.epoch
	a.mu.Unlock()
	if epoch < 3 {
		t.Fatal("did not renew", epoch)
	}
}
func TestRenewalUnreadApplication(t *testing.T) {
	policy := defaultRenewalPolicy()
	policy.softAge = 30 * time.Millisecond
	policy.hardAge = time.Second
	policy.timeout = 200 * time.Millisecond
	a, b := peerPair(t, peerOptions{policy: policy})
	done := make(chan error, 1)
	go func() { _, e := a.Write(bytes.Repeat([]byte{1}, peerWindow)); done <- e }()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	time.Sleep(120 * time.Millisecond)
	b.mu.Lock()
	epoch, buffered, e := b.epoch, b.recv.Len(), b.err
	b.mu.Unlock()
	if e != nil || epoch < 2 || buffered != peerWindow {
		t.Fatal("unread data blocked renewal", epoch, buffered, e)
	}
}

func TestRenewalSymmetricBoundary(t *testing.T) {
	policy := defaultRenewalPolicy()
	policy.rekey = 4
	policy.softBytes = 50000
	policy.hardBytes = 1 << 20
	a, b := peerPair(t, peerOptions{policy: policy})
	done := make(chan error, 1)
	payload := bytes.Repeat([]byte("rekey"), 100000)
	go func() { _, e := a.Write(payload); done <- e }()
	got := make([]byte, len(payload))
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, e := io.ReadFull(b, got); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil || !bytes.Equal(got, payload) {
		t.Fatal(e)
	}
}

func TestRenewalTransitions(t *testing.T) {
	for _, kind := range []byte{peerHS1, peerHS2, peerHS3, peerFinish, 255} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			a, b := peerPair(t, peerOptions{})
			b.mu.Lock()
			b.controls = append(b.controls, peerFrame{kind, epochBytes(1)})
			b.signalLocked()
			b.mu.Unlock()
			select {
			case <-a.done:
			case <-time.After(time.Second):
				t.Fatal("unexpected control survived")
			}
		})
	}
}
func TestRenewalRevocation(t *testing.T) {
	var revoked atomic.Bool
	policy := defaultRenewalPolicy()
	policy.softAge = 30 * time.Millisecond
	policy.hardAge = time.Second
	a, b := peerPair(t, peerOptions{policy: policy, PeerOptions: PeerOptions{Authorize: func(protocol.PeerContext) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	}}})
	revoked.Store(true)
	select {
	case <-a.done:
	case <-b.done:
	case <-time.After(time.Second):
		t.Fatal("revocation ignored at renewal")
	}
}
func TestRenewalHardLimits(t *testing.T) {
	for _, mode := range []string{"age", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			policy := defaultRenewalPolicy()
			if mode == "age" {
				policy.softAge = time.Hour
				policy.hardAge = 40 * time.Millisecond
			} else {
				policy.softBytes = 1 << 20
				policy.hardBytes = 1024
			}
			a, b := peerPair(t, peerOptions{policy: policy})
			if mode == "bytes" {
				if _, e := a.Write(make([]byte, 4096)); e == nil {
					t.Fatal("hard byte budget ignored")
				}
			}
			select {
			case <-a.done:
			case <-b.done:
			case <-time.After(time.Second):
				t.Fatal("hard limit ignored")
			}
		})
	}
}
func TestRenewalTimeout(t *testing.T) {
	policy := defaultRenewalPolicy()
	policy.softAge = time.Hour
	policy.hardAge = time.Second
	policy.timeout = 30 * time.Millisecond
	a, _ := peerPair(t, peerOptions{policy: policy})
	a.mu.Lock()
	a.phase = waitHS2
	a.renewStarted = time.Now()
	a.signalLocked()
	a.mu.Unlock()
	select {
	case <-a.done:
	case <-time.After(time.Second):
		t.Fatal("renewal timeout ignored")
	}
}
func TestPeerInvalidCreditAndBounds(t *testing.T) {
	a, b := peerPair(t, peerOptions{})
	b.mu.Lock()
	e := b.queueLocked(peerFrame{peerCredit, binary.BigEndian.AppendUint32(nil, 1)})
	b.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-a.done:
	case <-time.After(time.Second):
		t.Fatal("unsolicited credit accepted")
	}
	for _, f := range []peerFrame{{peerData, make([]byte, 32768)}, {peerHS1, make([]byte, 4097)}, {0, nil}} {
		if _, e := f.bytes(); e == nil {
			t.Fatal("invalid bound accepted")
		}
	}
}
func FuzzPeerRecord(f *testing.F) {
	f.Add([]byte{peerData, 1})
	f.Add([]byte{peerCredit, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > peerMaxPlain+1 {
			return
		}
		_, _ = parsePeerFrame(b)
	})
}

func TestRenewalBindingSubstitution(t *testing.T) {
	for _, field := range []string{"original", "previous", "identity", "epoch"} {
		t.Run(field, func(t *testing.T) {
			a, b := peerPair(t, peerOptions{})
			a.mu.Lock()
			switch field {
			case "original":
				a.original[0] ^= 1
			case "previous":
				a.binding[0] ^= 1
			case "identity":
				a.expected[0] ^= 1
			case "epoch":
				a.epoch = 1
			}
			e := a.startRenewalLocked()
			a.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			select {
			case <-a.done:
			case <-b.done:
			case <-time.After(time.Second):
				t.Fatal("renewal substitution survived")
			}
		})
	}
}
func TestRenewalDuplicateFinish(t *testing.T) {
	a, b := peerPair(t, peerOptions{})
	a.mu.Lock()
	e := a.startRenewalLocked()
	a.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		epoch := a.epoch
		a.mu.Unlock()
		b.mu.Lock()
		other := b.epoch
		b.mu.Unlock()
		if epoch == 1 && other == 1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("renewal did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	a.mu.Lock()
	body := append(append(epochBytes(a.epoch), 1), a.binding...)
	e = a.queueLocked(peerFrame{peerFinish, body})
	a.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-b.done:
	case <-time.After(time.Second):
		t.Fatal("duplicate FINISH accepted")
	}
}
