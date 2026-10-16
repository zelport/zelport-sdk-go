package secure

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// gatedCarrier stops the real record writer before a selected record's length
// header. It preserves deadline and Close behavior, and can fail halfway through
// the following ciphertext body. Only test code observes the local phase.
type gatedCarrier struct {
	net.Conn
	mu                               sync.Mutex
	match                            func() bool
	reached, resume, closed, changed chan struct{}
	deadline                         time.Time
	once                             sync.Once
	partial                          bool
	armed                            bool
}

func newGate(c net.Conn) *gatedCarrier {
	return &gatedCarrier{Conn: c, reached: make(chan struct{}), resume: make(chan struct{}), closed: make(chan struct{}), changed: make(chan struct{})}
}
func (g *gatedCarrier) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	g.deadline = t
	close(g.changed)
	g.changed = make(chan struct{})
	g.mu.Unlock()
	return g.Conn.SetWriteDeadline(t)
}
func (g *gatedCarrier) Close() error { g.once.Do(func() { close(g.closed) }); return g.Conn.Close() }
func (g *gatedCarrier) Write(p []byte) (int, error) {
	g.mu.Lock()
	match := g.match
	partial := g.partial && g.armed && len(p) > 4
	g.mu.Unlock()
	if len(p) == 4 && match != nil && match() {
		g.mu.Lock()
		g.match = nil
		g.armed = true
		close(g.reached)
		g.mu.Unlock()
		for {
			g.mu.Lock()
			deadline, changed := g.deadline, g.changed
			g.mu.Unlock()
			var timer *time.Timer
			var timeout <-chan time.Time
			if !deadline.IsZero() {
				timer = time.NewTimer(time.Until(deadline))
				timeout = timer.C
			}
			select {
			case <-g.resume:
				if timer != nil {
					timer.Stop()
				}
				return g.Conn.Write(p)
			case <-g.closed:
				if timer != nil {
					timer.Stop()
				}
				return 0, net.ErrClosed
			case <-changed:
				if timer != nil {
					timer.Stop()
				}
				continue
			case <-timeout:
				return 0, os.ErrDeadlineExceeded
			}
		}
	}
	if partial {
		n, e := g.Conn.Write(p[:min(7, len(p))])
		if e != nil {
			return n, e
		}
		return n, io.ErrUnexpectedEOF
	}
	return g.Conn.Write(p)
}
func TestRenewalCloseEveryTransition(t *testing.T) {
	for _, stage := range []string{"HS1", "HS2", "HS3", "consumer-FINISH", "provider-FINISH"} {
		for _, action := range []string{"close", "cancel", "deadline", "partial", "renewal-timeout"} {
			t.Run(stage+"/"+action, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				x, y := net.Pipe()
				ga, gb := newGate(x), newGate(y)
				options := peerOptions{}
				if action == "renewal-timeout" {
					options.policy = defaultRenewalPolicy()
					options.policy.timeout = 40 * time.Millisecond
				}
				a, b := peerPairContext(t, ctx, options, ga, gb)
				gate, target := ga, a
				if stage == "HS2" || stage == "provider-FINISH" {
					gate, target = gb, b
				}
				gate.mu.Lock()
				gate.partial = action == "partial"
				gate.match = func() bool {
					target.mu.Lock()
					defer target.mu.Unlock()
					switch stage {
					case "HS1":
						return target.phase == waitHS2
					case "HS2":
						return target.phase == waitHS3
					case "HS3":
						return target.phase == waitProviderFinish && target.nextTX != nil
					case "consumer-FINISH":
						return target.phase == waitProviderFinish && target.nextTX == nil
					default:
						return target.phase == sendProviderFinish
					}
				}
				gate.mu.Unlock()
				// Fill the receive window, leaving a pending caller Write across the handshake.
				written := make(chan error, 1)
				go func() { _, e := a.Write(make([]byte, peerWindow*2)); written <- e }()
				until := time.Now().Add(time.Second)
				for {
					a.mu.Lock()
					credit := a.sendCredit
					sent := 0
					if a.request != nil {
						sent = a.request.sent
					}
					a.mu.Unlock()
					if credit == 0 && sent == peerWindow {
						break
					}
					if time.Now().After(until) {
						t.Fatal("window did not fill")
					}
					time.Sleep(time.Millisecond)
				}
				a.mu.Lock()
				e := a.startRenewalLocked()
				a.mu.Unlock()
				if e != nil {
					t.Fatal(e)
				}
				select {
				case <-gate.reached:
				case <-time.After(time.Second):
					t.Fatal("real handshake did not reach gate")
				}
				switch action {
				case "close":
					target.Close()
				case "cancel":
					cancel()
				case "deadline":
					target.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
				case "partial":
					close(gate.resume)
				}
				select {
				case e := <-written:
					if e == nil {
						t.Fatal("failed carrier acknowledged pending application bytes")
					}
				case <-time.After(time.Second):
					t.Fatal("pending write stranded")
				}
				joined := make(chan struct{})
				go func() { a.Close(); b.Close(); close(joined) }()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Fatal("workers stranded at barrier")
				}
				if action == "deadline" {
					target.mu.Lock()
					e := target.err
					target.mu.Unlock()
					if !errors.Is(e, os.ErrDeadlineExceeded) {
						t.Fatal("caller write deadline lost", e)
					}
				}
			})
		}
	}
}
func TestPeerControlFrameLimit(t *testing.T) {
	if _, e := (peerFrame{peerHS1, make([]byte, 4095)}).bytes(); e != nil {
		t.Fatal(e)
	}
	if _, e := (peerFrame{peerHS1, make([]byte, 4096)}).bytes(); e == nil {
		t.Fatal("type byte not counted in control limit")
	}
}
