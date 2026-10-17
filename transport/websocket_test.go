package transport

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestDialTLSUsesOnlyRelayV1Endpoint(t *testing.T) {
	for _, address := range []string{"ws://relay.example", "ws://relay.example/", "ws://relay.example/v1/ws"} {
		t.Run(address, func(t *testing.T) {
			var path string
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				path = request.URL.Path
				return nil, errors.New("test transport stop")
			})}
			if _, err := DialTLS(context.Background(), address, nil, "control", client); err == nil {
				t.Fatal("test transport error hidden")
			}
			if path != "/v1/ws" {
				t.Fatalf("request path = %q, want /v1/ws", path)
			}
		})
	}

	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected request")
	})}
	if _, err := DialTLS(context.Background(), "ws://relay.example/v2/ws", nil, "control", client); err == nil {
		t.Fatal("previous endpoint accepted")
	}
	if called {
		t.Fatal("previous endpoint reached transport")
	}
}
