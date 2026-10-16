package secure

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"github.com/flynn/noise"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"net"
	"time"
)

// confirmPeer binds the initial epoch and role under the newly established keys.
// Admission uses its own confirmation and never interprets peer record types.
func confirmPeer(c *Conn, initiator bool) error {
	body := func(role bool) []byte {
		v := byte(0)
		if role {
			v = 1
		}
		return append(append(append([]byte{peerFinish}, epochBytes(0)...), v), c.binding...)
	}
	write := func() error { _, e := c.Write(body(initiator)); return e }
	read := func() error {
		expected := body(!initiator)
		got := make([]byte, len(expected))
		_, e := io.ReadFull(c, got)
		if e == nil && !bytes.Equal(got, expected) {
			e = errors.New("invalid initial peer confirmation")
		}
		return e
	}
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

func Peer(ctx context.Context, c net.Conn, initiator bool, identity protocol.Identity, token []byte, peer protocol.PeerContext, route protocol.RelayRoute, options PeerOptions) (net.Conn, error) {
	return peerWithOptions(ctx, c, initiator, identity, token, peer, route, peerOptions{PeerOptions: options})
}
func peerWithOptions(ctx context.Context, c net.Conn, initiator bool, identity protocol.Identity, token []byte, peer protocol.PeerContext, route protocol.RelayRoute, options peerOptions) (result net.Conn, err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	c.SetDeadline(deadline)
	raw, err := peer.Bytes()
	if err != nil {
		return nil, err
	}
	pub, err := Public(identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	ownID, ownKey, expected := peer.Provider, peer.ProviderKey, peer.ConsumerKey
	if initiator {
		ownID, ownKey, expected = peer.Consumer, peer.ConsumerKey, peer.ProviderKey
	}
	if identity.ID != ownID || base64.RawURLEncoding.EncodeToString(pub) != ownKey {
		return nil, errors.New("local identity mismatch")
	}
	expectedRoute, e := PeerRoute(token, peer)
	if e != nil {
		return nil, e
	}
	if expectedRoute != route {
		return nil, errors.New("peer routing mismatch")
	}
	routeBytes, e := route.Bytes()
	if e != nil {
		return nil, e
	}
	raw = append(append(raw, '\n'), routeBytes...)
	key, err := Derive(token, "peer-psk")
	if err != nil {
		return nil, err
	}
	expectedKey, _ := protocol.DecodeKey(expected)
	cfg := noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: noise.HandshakeXX, Initiator: initiator, PresharedKey: key[:], PresharedKeyPlacement: 3, StaticKeypair: noise.DHKey{Private: identity.PrivateKey, Public: pub}, Prologue: append([]byte("snitzel-cloud/v3/consumer-provider/"), raw...)}
	secure, err := handshake(c, cfg, 3, expectedKey)
	if err != nil {
		return nil, err
	}
	secure.SetDeadline(deadline)
	if options.Authorize != nil {
		if err = options.Authorize(peer); err != nil {
			return nil, err
		}
	}
	if err = confirmPeer(secure, initiator); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	secure.SetDeadline(time.Time{})
	return newPeerConn(ctx, c, secure.tx, secure.rx, options, cfg, secure.binding, expectedKey, peer), nil
}

func PeerRoute(secret []byte, p protocol.PeerContext) (protocol.RelayRoute, error) {
	a, e := CatalogRouteID(secret, p.Consumer)
	if e != nil {
		return protocol.RelayRoute{}, e
	}
	b, e := CatalogRouteID(secret, p.Provider)
	return protocol.RelayRoute{Version: protocol.Version, Group: p.Group, ConsumerRoute: a, ProviderRoute: b, Session: p.Session}, e
}
