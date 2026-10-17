package secure

import (
	"testing"

	"github.com/zelport/zelport-sdk-go/protocol"
)

func TestRelayProtocolIdentity(t *testing.T) {
	if protocol.Version != 1 {
		t.Fatalf("protocol version = %d, want 1", protocol.Version)
	}
	if protocol.RelayEndpoint != "/v1/ws" {
		t.Fatalf("relay endpoint = %q", protocol.RelayEndpoint)
	}
	if protocol.TraceHeader != "X-Zelport-Relay-Trace" {
		t.Fatalf("trace header = %q", protocol.TraceHeader)
	}
	contexts := map[string]string{
		"base":              protocol.CryptoContext,
		"catalog":           protocol.CatalogCryptoContext,
		"client relay":      protocol.ClientRelayCryptoContext,
		"open client relay": protocol.OpenClientRelayCryptoContext,
		"consumer provider": protocol.ConsumerProviderCryptoContext,
		"renewal":           protocol.RenewalCryptoContext,
	}
	want := map[string]string{
		"base":              "zelport-relay/v1",
		"catalog":           "zelport-relay/v1/catalog",
		"client relay":      "zelport-relay/v1/client-relay/",
		"open client relay": "zelport-relay/v1/client-relay/open/",
		"consumer provider": "zelport-relay/v1/consumer-provider/",
		"renewal":           "zelport-relay/v1/renewal/",
	}
	for name, got := range contexts {
		if got != want[name] {
			t.Errorf("%s context = %q, want %q", name, got, want[name])
		}
	}
}
