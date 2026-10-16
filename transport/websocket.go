// Package transport owns bounded WebSocket connections with Noise admission.
package transport

import (
	"context"
	"errors"
	"github.com/coder/websocket"
	"github.com/zelport/zelport-sdk-go/protocol"
	"github.com/zelport/zelport-sdk-go/secure"
	"net"
	"net/http"
	"net/url"
	"time"
)

type socket struct {
	net.Conn
	ws *websocket.Conn
}

func (c *socket) Close() error { return c.ws.CloseNow() }
func Wrap(ctx context.Context, ws *websocket.Conn) net.Conn {
	c := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(64 << 10)
	return &socket{c, ws}
}
func Dial(ctx context.Context, address string, token []byte, purpose string) (net.Conn, error) {
	return DialTLS(ctx, address, token, purpose, nil)
}

// DialTLS accepts a supplied TLS configuration through the HTTP transport for controlled deployments/tests.
func DialTLS(ctx context.Context, address string, token []byte, purpose string, client *http.Client) (net.Conn, error) {
	u, e := url.Parse(address)
	if e != nil || u.Host == "" || (u.Scheme != "ws" && u.Scheme != "wss") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid relay URL")
	}
	u.Path = "/v3/ws"
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		client = &http.Client{Transport: tr}
	} else {
		copy := *client
		client = &copy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("relay redirects are forbidden") }
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ws, _, e := websocket.Dial(dialCtx, u.String(), &websocket.DialOptions{HTTPClient: client, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return nil, errors.New("relay connection failed")
	}
	c := Wrap(ctx, ws)
	return secure.Admit(dialCtx, c, true, token, protocol.NewHello(purpose))
}
