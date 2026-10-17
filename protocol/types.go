// Package protocol defines the versioned, bounded Ports over Relay wire format.
package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

const (
	Version                       = 1
	RelayEndpoint                 = "/v1/ws"
	TraceHeader                   = "X-Zelport-Relay-Trace"
	CryptoContext                 = "zelport-relay/v1"
	CatalogCryptoContext          = CryptoContext + "/catalog"
	ClientRelayCryptoContext      = CryptoContext + "/client-relay/"
	OpenClientRelayCryptoContext  = CryptoContext + "/client-relay/open/"
	ConsumerProviderCryptoContext = CryptoContext + "/consumer-provider/"
	RenewalCryptoContext          = CryptoContext + "/renewal/"
)
const MaxServices = 256
const MaxKnownCatalog = 32
const MaxControl = 128 << 10
const MaxSnapshot = 2 << 20

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+localhost$`)

func ValidID(v string) bool     { return uuidPattern.MatchString(v) }
func ValidDomain(v string) bool { return len(v) <= 253 && domainPattern.MatchString(v) }
func ID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func Token() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func DecodeKey(v string) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(v)
	if e != nil || len(b) != 32 {
		return nil, fmt.Errorf("expected a 32-byte Base64url key")
	}
	return b, nil
}

type Identity struct {
	ID         string
	PrivateKey []byte
}
type Service struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Domain string `json:"domain"`
}
type Import struct {
	Group       string `json:"group"`
	DeviceID    string `json:"device_id"`
	ServiceID   string `json:"service_id"`
	ProviderKey string `json:"provider_key"`
}
type OpenRequest struct {
	Kind      string     `json:"kind"`
	Admin     *AdminOpen `json:"admin,omitempty"`
	ServiceID string     `json:"service_id"`
	Authority string     `json:"authority"`
	Trace     string     `json:"trace"`
}

type Message struct {
	Type       string            `json:"type"`
	Known      map[string]string `json:"known,omitempty"`
	ID         string            `json:"id,omitempty"`
	Error      string            `json:"error,omitempty"`
	Record     json.RawMessage   `json:"record,omitempty"`
	Group      string            `json:"group,omitempty"`
	Device     string            `json:"device,omitempty"`
	Control    string            `json:"control,omitempty"`
	Capability string            `json:"capability,omitempty"`
	Route      *RelayRoute       `json:"route,omitempty"`
	Open       *OpenRequest      `json:"open,omitempty"`
}
