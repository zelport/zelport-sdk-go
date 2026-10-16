// Package client maintains outbound relay connections and authenticated peer sessions.
package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/hashicorp/yamux"
	"github.com/zelport/zelport-sdk-go/protocol"
	"github.com/zelport/zelport-sdk-go/secure"
	"github.com/zelport/zelport-sdk-go/transport"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Registry interface {
	Catalog(context.Context) (protocol.Record, error)
	Open(context.Context, protocol.PeerContext, protocol.OpenRequest) (net.Conn, error)
}
type Options struct {
	RelayURL                string
	AccessToken, GroupToken []byte
	Identity                protocol.Identity
	Registry                Registry
	AcceptRecord            func(protocol.Record, []byte) error
	HTTPClient              *http.Client
}
type Status struct {
	Connected bool              `json:"connected"`
	Error     string            `json:"error,omitempty"`
	Records   []protocol.Record `json:"records"`
}
type cached struct {
	record                  protocol.Record
	digest                  string
	routeID, envelopeDigest string
}
type session struct {
	mux   *yamux.Session
	slots chan struct{}
	last  time.Time
}
type Client struct {
	opts                       Options
	ctx                        context.Context
	cancel                     context.CancelFunc
	mu                         sync.Mutex
	acceptMu                   sync.Mutex
	closed, running, connected bool
	lastError                  string
	publicationWarning         string
	ctl                        *control
	records                    map[string]cached
	sessions                   map[string]*session
	dialing                    map[string]chan struct{}
	conns                      map[net.Conn]bool
	sessionSlots, streamSlots  chan struct{}
	notify, refresh            chan struct{}
	group                      string
}
type control struct {
	conn    net.Conn
	mu      sync.Mutex
	write   sync.Mutex
	pending map[string]chan protocol.Message
	done    chan struct{}
	once    sync.Once
	cap     string
}

func (c *control) close() { c.once.Do(func() { close(c.done); c.conn.Close() }) }
func New(o Options) (*Client, error) {
	if (len(o.AccessToken) != 0 && len(o.AccessToken) != 32) || len(o.GroupToken) != 32 || !protocol.ValidID(o.Identity.ID) || len(o.Identity.PrivateKey) != 32 || o.Registry == nil {
		return nil, errors.New("invalid cloud client configuration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	locator, _ := secure.Derive(o.GroupToken, "group-locator")
	return &Client{opts: o, ctx: ctx, cancel: cancel, records: map[string]cached{}, sessions: map[string]*session{}, dialing: map[string]chan struct{}{}, conns: map[net.Conn]bool{}, sessionSlots: make(chan struct{}, 16), streamSlots: make(chan struct{}, 128), notify: make(chan struct{}, 1), refresh: make(chan struct{}, 1), group: hex.EncodeToString(locator[:])}, nil
}
func (c *Client) Notify() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}
func (c *Client) Refresh() {
	select {
	case c.refresh <- struct{}{}:
	default:
	}
}
func (c *Client) Snapshot() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{Connected: c.connected, Error: c.lastError, Records: []protocol.Record{}}
	if c.publicationWarning != "" {
		if s.Error != "" {
			s.Error += "; "
		}
		s.Error += c.publicationWarning
	}
	for _, v := range c.records {
		r := v.record
		r.Services = append([]protocol.Service{}, r.Services...)
		s.Records = append(s.Records, r)
	}
	return s
}
func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	c.connected = false
	ctl := c.ctl
	connections := make([]net.Conn, 0, len(c.conns))
	for v := range c.conns {
		connections = append(connections, v)
	}
	sessions := make([]*session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()
	if ctl != nil {
		ctl.close()
	}
	for _, v := range connections {
		v.Close()
	}
	for _, s := range sessions {
		s.mux.Close()
	}
	return nil
}
func (c *Client) track(conn net.Conn) (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	c.conns[conn] = true
	return func() { c.mu.Lock(); delete(c.conns, conn); c.mu.Unlock() }, nil
}
func backoff(attempt int) time.Duration {
	if attempt > 5 {
		attempt = 5
	}
	d := time.Second * time.Duration(1<<attempt)
	var b [1]byte
	rand.Read(b[:])
	d += time.Duration(float64(d) * 0.2 * float64(b[0]) / 255)
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}
func (c *Client) Run(parent context.Context) error {
	c.mu.Lock()
	if c.running || c.closed {
		c.mu.Unlock()
		return errors.New("client already running or closed")
	}
	c.running = true
	c.mu.Unlock()
	stop := context.AfterFunc(parent, func() { c.Close() })
	defer stop()
	defer c.Close()
	attempt := 0
	for c.ctx.Err() == nil {
		start := time.Now()
		e := c.runConnection()
		c.mu.Lock()
		c.connected = false
		if e != nil {
			c.lastError = e.Error()
		}
		connections := make([]net.Conn, 0, len(c.conns))
		for conn := range c.conns {
			connections = append(connections, conn)
		}
		sessions := c.sessions
		c.sessions = map[string]*session{}
		c.mu.Unlock()
		for _, s := range sessions {
			s.mux.Close()
		}
		for _, conn := range connections {
			conn.Close()
		}
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}
		if time.Since(start) >= 60*time.Second {
			attempt = 0
		}
		timer := time.NewTimer(backoff(attempt))
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return c.ctx.Err()
		case <-timer.C:
		}
		attempt++
	}
	return c.ctx.Err()
}
func (c *Client) runConnection() error {
	conn, e := transport.DialTLS(c.ctx, c.opts.RelayURL, c.opts.AccessToken, "control", c.opts.HTTPClient)
	if e != nil {
		return e
	}
	release, e := c.track(conn)
	if e != nil {
		return e
	}
	defer release()
	ctl := &control{conn: conn, pending: map[string]chan protocol.Message{}, done: make(chan struct{})}
	defer ctl.close()
	c.mu.Lock()
	c.ctl = ctl
	c.mu.Unlock()
	go c.readControl(ctl)
	if e = c.publish(ctl); e != nil {
		return e
	}
	if e = c.catalog(ctl); e != nil {
		return e
	}
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-ctl.done:
			return errors.New("relay disconnected")
		case <-c.notify:
			e = c.publishUpdate(ctl)
			if e == nil {
				e = c.catalog(ctl)
			}
		case <-c.refresh:
			e = c.catalog(ctl)
		case <-ticker.C:
			e = c.publishUpdate(ctl)
			if e == nil {
				e = c.catalog(ctl)
			}
			c.prune()
		}
		if e != nil {
			return e
		}
	}
}
func (c *Client) readControl(ctl *control) {
	defer ctl.close()
	for {
		ctl.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		var m protocol.Message
		if protocol.ReadJSON(ctl.conn, &m) != nil {
			return
		}
		switch m.Type {
		case "changed":
			c.Refresh()
		case "offer":
			select {
			case c.sessionSlots <- struct{}{}:
				go func() { defer func() { <-c.sessionSlots }(); c.offer(ctl, m) }()
			default:
			}
		case "record", "result":
			ctl.mu.Lock()
			ch := ctl.pending[m.ID]
			ctl.mu.Unlock()
			if ch == nil {
				return
			}
			select {
			case ch <- m:
			default:
				return
			}
		default:
			return
		}
	}
}
func (c *Client) request(ctl *control, m protocol.Message) ([]protocol.Message, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	if m.ID == "" {
		m.ID = protocol.ID()
	}
	ch := make(chan protocol.Message, 34)
	ctl.mu.Lock()
	if len(ctl.pending) >= 16 {
		ctl.mu.Unlock()
		return nil, errors.New("control request limit")
	}
	ctl.pending[m.ID] = ch
	ctl.mu.Unlock()
	defer func() { ctl.mu.Lock(); delete(ctl.pending, m.ID); ctl.mu.Unlock() }()
	ctl.write.Lock()
	ctl.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	e := protocol.WriteJSON(ctl.conn, m)
	ctl.write.Unlock()
	if e != nil {
		return nil, e
	}
	results := []protocol.Message{}
	size := 0
	for {
		select {
		case <-ctx.Done():
			ctl.close()
			return nil, ctx.Err()
		case <-ctl.done:
			return nil, errors.New("relay disconnected")
		case r := <-ch:
			if r.Error != "" {
				return nil, errors.New(r.Error)
			}
			results = append(results, r)
			size += len(r.Record)
			if size > protocol.MaxSnapshot || len(results) > 33 {
				return nil, errors.New("catalog limit exceeded")
			}
			if r.Type == "result" {
				return results, nil
			}
		}
	}
}
func (c *Client) publish(ctl *control) error {
	r, e := c.opts.Registry.Catalog(c.ctx)
	if e != nil {
		return &publicationError{e}
	}
	r.Group = c.group
	r.Version = protocol.Version
	if r.DeviceID != c.opts.Identity.ID {
		return &publicationError{errors.New("registry identity mismatch")}
	}
	raw, e := secure.SealCatalog(r, c.opts.GroupToken)
	if e != nil {
		return &publicationError{e}
	}
	message := protocol.Message{Type: "register", ID: protocol.ID(), Record: raw}
	if _, e := protocol.EncodeMessage(message); e != nil {
		return &publicationError{e}
	}
	messages, e := c.request(ctl, message)
	if e != nil {
		return e
	}
	c.mu.Lock()
	c.publicationWarning = ""
	c.mu.Unlock()
	ctl.mu.Lock()
	ctl.cap = messages[len(messages)-1].Control
	ctl.mu.Unlock()
	return c.accept(raw)
}
func (c *Client) accept(raw []byte) error {
	c.acceptMu.Lock()
	defer c.acceptMu.Unlock()
	r, plain, e := secure.OpenCatalog(raw, c.opts.GroupToken, time.Now())
	if e != nil {
		return e
	}
	if r.Group != c.group {
		return errors.New("catalog group mismatch")
	}
	digest := protocol.Digest(plain)
	c.mu.Lock()
	old, ok := c.records[r.DeviceID]
	full := !ok && len(c.records) >= 1024
	c.mu.Unlock()
	if full {
		return errors.New("catalog identity history limit")
	}
	if ok && (r.PublicKey != old.record.PublicKey || r.Sequence < old.record.Sequence || (r.Sequence == old.record.Sequence && digest != old.digest)) {
		return errors.New("catalog identity substitution or replay")
	}
	if c.opts.AcceptRecord != nil {
		if e = c.opts.AcceptRecord(r, plain); e != nil {
			return e
		}
	}
	c.mu.Lock()
	routeID, _ := secure.CatalogRouteID(c.opts.GroupToken, r.DeviceID)
	c.records[r.DeviceID] = cached{record: r, digest: digest, routeID: routeID, envelopeDigest: protocol.Digest(raw)}
	c.mu.Unlock()
	return nil
}
func (c *Client) catalog(ctl *control) error {
	messages, e := c.request(ctl, protocol.Message{Type: "catalog", Known: c.knownCatalog()})
	if e != nil {
		return e
	}
	warning := ""
	for _, m := range messages {
		if m.Type == "record" {
			if e = c.accept(m.Record); e != nil {
				warning = "Rejected catalog record: " + e.Error()
			}
		}
	}
	c.mu.Lock()
	c.lastError = warning
	c.mu.Unlock()
	return nil
}
func (c *Client) lookup(ref protocol.Import) (protocol.Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.records[ref.DeviceID]
	if !c.connected || !ok || ref.Group != c.group || v.record.PublicKey != ref.ProviderKey || v.record.ExpiresAt <= time.Now().Unix() || ref.DeviceID == c.opts.Identity.ID {
		return protocol.Record{}, errors.New("authenticated provider unavailable")
	}
	if _, e := v.record.Authority(ref.ServiceID); e != nil {
		return protocol.Record{}, e
	}
	return v.record, nil
}
func (c *Client) prune() {
	c.mu.Lock()
	var closeList []*session
	for key, s := range c.sessions {
		if s.mux.IsClosed() || (len(s.slots) == 0 && time.Since(s.last) > 60*time.Second) {
			closeList = append(closeList, s)
			delete(c.sessions, key)
		}
	}
	c.mu.Unlock()
	for _, s := range closeList {
		s.mux.Close()
	}
}
func muxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 32
	cfg.MaxStreamWindowSize = 256 << 10
	cfg.StreamOpenTimeout = 5 * time.Second
	cfg.StreamCloseTimeout = time.Second
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}
func (c *Client) session(ctx context.Context, ref protocol.Import) (*session, error) {
	key := ref.Group + "/" + ref.DeviceID + "/" + ref.ProviderKey
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		if s := c.sessions[key]; s != nil && !s.mux.IsClosed() {
			s.last = time.Now()
			c.mu.Unlock()
			return s, nil
		}
		if wait := c.dialing[key]; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		wait := make(chan struct{})
		c.dialing[key] = wait
		c.mu.Unlock()
		s, e := c.establish(ctx, ref)
		return c.finishEstablish(key, s, e)
	}
}
func (c *Client) finishEstablish(key string, s *session, e error) (*session, error) {
	c.mu.Lock()
	wait := c.dialing[key]
	delete(c.dialing, key)
	closeSession := false
	if e == nil && !c.closed {
		c.sessions[key] = s
	} else if s != nil {
		closeSession = true
		e = net.ErrClosed
	}
	if wait != nil {
		close(wait)
	}
	c.mu.Unlock()
	// Closing joins the E2E reader, whose authorization callback also takes mu.
	if closeSession {
		s.mux.Close()
	}
	return s, e
}
func (c *Client) establish(ctx context.Context, ref protocol.Import) (*session, error) {
	if _, e := c.lookup(ref); e != nil {
		return nil, e
	}
	select {
	case c.sessionSlots <- struct{}{}:
	default:
		return nil, errors.New("peer session limit")
	}
	owned := true
	defer func() {
		if owned {
			<-c.sessionSlots
		}
	}()
	c.mu.Lock()
	ctl := c.ctl
	own := c.records[c.opts.Identity.ID].record
	c.mu.Unlock()
	if ctl == nil {
		return nil, errors.New("relay unavailable")
	}
	p := protocol.PeerContext{Version: protocol.Version, Group: c.group, Consumer: c.opts.Identity.ID, Provider: ref.DeviceID, ConsumerKey: own.PublicKey, ProviderKey: ref.ProviderKey, Session: protocol.RandomNonce()}
	route, e := secure.PeerRoute(c.opts.GroupToken, p)
	if e != nil {
		return nil, e
	}
	conn, e := transport.DialTLS(c.ctx, c.opts.RelayURL, c.opts.AccessToken, "connect", c.opts.HTTPClient)
	if e != nil {
		return nil, e
	}
	release, e := c.track(conn)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			conn.Close()
			release()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	ctl.mu.Lock()
	cap := ctl.cap
	ctl.mu.Unlock()
	if e = protocol.WriteJSON(conn, protocol.Message{Type: "connect", Route: &route, Control: cap}); e != nil {
		return nil, e
	}
	var ack protocol.Message
	if e = protocol.ReadJSON(conn, &ack); e != nil || ack.Error != "" {
		return nil, errors.New("provider tunnel unavailable")
	}
	secured, e := secure.Peer(c.ctx, conn, true, c.opts.Identity, c.opts.GroupToken, p, route, secure.PeerOptions{Authorize: c.authorizePeer})
	if e != nil {
		return nil, e
	}
	mux, e := yamux.Client(secured, muxConfig())
	if e != nil {
		return nil, e
	}
	s := &session{mux: mux, slots: make(chan struct{}, 32), last: time.Now()}
	owned = false
	keep = true
	go func() { <-mux.CloseChan(); conn.Close(); release(); <-c.sessionSlots }()
	return s, nil
}

type ownedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *ownedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (c *Client) Open(ctx context.Context, ref protocol.Import, request protocol.OpenRequest) (net.Conn, error) {
	if e := request.Validate(); e != nil {
		return nil, e
	}
	record, e := c.lookup(ref)
	if e != nil {
		return nil, e
	}
	kind := ""
	for _, service := range record.Services {
		if service.ID == ref.ServiceID {
			kind = service.Kind
		}
	}
	authority, e := record.Authority(ref.ServiceID)
	if e != nil || kind != request.Kind || request.ServiceID != ref.ServiceID || request.Authority != authority {
		return nil, errors.New("service authority changed; refresh catalog")
	}
	select {
	case c.streamSlots <- struct{}{}:
	default:
		return nil, errors.New("stream limit exceeded")
	}
	keep := false
	defer func() {
		if !keep {
			<-c.streamSlots
		}
	}()
	s, e := c.session(ctx, ref)
	if e != nil {
		return nil, e
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return nil, errors.New("provider stream limit")
	}
	held := true
	defer func() {
		if held {
			<-s.slots
		}
	}()
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	stream, e := s.mux.OpenStream()
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	if e = protocol.WriteJSON(stream, protocol.Message{Type: "open", Open: &request}); e != nil {
		stop()
		stream.Close()
		return nil, e
	}
	var ack protocol.Message
	e = protocol.ReadJSON(stream, &ack)
	if e != nil || ack.Type != "opened" || ack.Error != "" {
		stop()
		stream.Close()
		return nil, errors.New("provider rejected service")
	}
	stream.SetDeadline(time.Time{})
	keep = true
	held = false
	return &ownedConn{Conn: stream, release: func() {
		stop()
		c.mu.Lock()
		s.last = time.Now()
		c.mu.Unlock()
		<-s.slots
		<-c.streamSlots
	}}, nil
}
func (c *Client) offer(ctl *control, m protocol.Message) {
	if m.Route == nil {
		return
	}
	route := *m.Route
	p, e := c.resolveRoute(route)
	if e != nil {
		c.Refresh()
		return
	}
	conn, e := transport.DialTLS(c.ctx, c.opts.RelayURL, c.opts.AccessToken, "join", c.opts.HTTPClient)
	if e != nil {
		return
	}
	defer conn.Close()
	release, e := c.track(conn)
	if e != nil {
		return
	}
	defer release()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	ctl.mu.Lock()
	cap := ctl.cap
	ctl.mu.Unlock()
	if protocol.WriteJSON(conn, protocol.Message{Type: "join", Route: &route, Capability: m.Capability, Control: cap}) != nil {
		return
	}
	var ack protocol.Message
	if protocol.ReadJSON(conn, &ack) != nil || ack.Error != "" {
		return
	}
	secured, e := secure.Peer(c.ctx, conn, false, c.opts.Identity, c.opts.GroupToken, p, route, secure.PeerOptions{Authorize: c.authorizePeer})
	if e != nil {
		return
	}
	mux, e := yamux.Server(secured, muxConfig())
	if e != nil {
		return
	}
	defer mux.Close()
	slots := make(chan struct{}, 32)
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	idleDone := make(chan struct{})
	defer close(idleDone)
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-idleDone:
				return
			case <-ticker.C:
				if len(slots) == 0 && time.Since(time.Unix(0, last.Load())) > 60*time.Second {
					mux.Close()
					return
				}
			}
		}
	}()
	for {
		stream, e := mux.AcceptStreamWithContext(c.ctx)
		if e != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			select {
			case c.streamSlots <- struct{}{}:
				go func() {
					defer func() { last.Store(time.Now().UnixNano()); <-slots; <-c.streamSlots }()
					c.serve(stream, p)
				}()
			default:
				<-slots
				stream.Close()
			}
		default:
			stream.Close()
		}
	}
}
func (c *Client) serve(stream net.Conn, peer protocol.PeerContext) {
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	var m protocol.Message
	if protocol.ReadJSON(stream, &m) != nil || m.Type != "open" || m.Open == nil || m.Open.Validate() != nil {
		return
	}
	backend, e := c.opts.Registry.Open(c.ctx, peer, *m.Open)
	if e != nil {
		protocol.WriteJSON(stream, protocol.Message{Type: "opened", Error: "unavailable"})
		return
	}
	defer backend.Close()
	if protocol.WriteJSON(stream, protocol.Message{Type: "opened"}) != nil {
		return
	}
	stream.SetDeadline(time.Time{})
	bridge(stream, backend)
}
func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copySide := func(dst, src net.Conn) {
		io.CopyBuffer(dst, src, make([]byte, 32<<10))
		a.Close()
		b.Close()
		done <- struct{}{}
	}
	go copySide(a, b)
	go copySide(b, a)
	<-done
	<-done
}

func (c *Client) resolveRoute(route protocol.RelayRoute) (protocol.PeerContext, error) {
	var p protocol.PeerContext
	if _, e := route.Bytes(); e != nil {
		return p, e
	}
	ownRoute, _ := secure.CatalogRouteID(c.opts.GroupToken, c.opts.Identity.ID)
	if route.Group != c.group || route.ProviderRoute != ownRoute {
		return p, errors.New("routing mismatch")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	own, ok := c.records[c.opts.Identity.ID]
	if !ok || own.record.ExpiresAt <= time.Now().Unix() {
		return p, errors.New("local catalog unavailable")
	}
	for _, v := range c.records {
		rid, _ := secure.CatalogRouteID(c.opts.GroupToken, v.record.DeviceID)
		if rid == route.ConsumerRoute && v.record.ExpiresAt > time.Now().Unix() {
			return protocol.PeerContext{Version: protocol.Version, Group: c.group, Consumer: v.record.DeviceID, Provider: own.record.DeviceID, ConsumerKey: v.record.PublicKey, ProviderKey: own.record.PublicKey, Session: route.Session}, nil
		}
	}
	return p, errors.New("authenticated peer unavailable")
}

func (c *Client) authorizePeer(p protocol.PeerContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil || p.Group != c.group {
		return net.ErrClosed
	}
	for _, ref := range []struct{ id, key string }{{p.Consumer, p.ConsumerKey}, {p.Provider, p.ProviderKey}} {
		v, ok := c.records[ref.id]
		if !ok || v.record.PublicKey != ref.key || v.record.ExpiresAt <= time.Now().Unix() {
			return errors.New("peer authorization expired")
		}
	}
	return nil
}

type publicationError struct{ error }

func (c *Client) publishUpdate(ctl *control) error {
	e := c.publish(ctl)
	var rejected *publicationError
	if errors.As(e, &rejected) {
		c.mu.Lock()
		c.publicationWarning = "Publication rejected: " + e.Error()
		c.mu.Unlock()
		return nil
	}
	return e
}

// Hints describe only authenticated, unexpired envelopes. A relay omission is
// never an authorization or freshness statement and cannot extend their expiry.
func (c *Client) knownCatalog() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	known := make(map[string]string)
	now := time.Now().Unix()
	for _, record := range c.records {
		if record.record.ExpiresAt > now && record.envelopeDigest != "" {
			known[record.routeID] = record.envelopeDigest
			if len(known) == protocol.MaxKnownCatalog {
				break
			}
		}
	}
	return known
}
