package secure

import (
	"bytes"
	"compress/flate"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/zelport/zelport-sdk-go/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

func compressedFixture(t testing.TB, count int) (protocol.Record, []byte, []byte) {
	t.Helper()
	r, secret := catalogFixture()
	r.Services = nil
	for i := 0; i < count; i++ {
		r.Services = append(r.Services, protocol.Service{ID: protocol.ID(), Domain: fmt.Sprintf("project-%d.localhost", i), Kind: protocol.Application})
	}
	plain, err := protocol.CanonicalRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	return r, secret, plain
}

func TestCatalogCompressionSavings(t *testing.T) {
	for _, count := range []int{1, 25, 100, 256} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, secret, plain := compressedFixture(t, count)
			raw, err := SealCatalog(r, secret)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := protocol.ParseCatalogEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(envelope.Ciphertext) >= len(plain)+16 {
				t.Fatalf("catalog not compressed: plaintext=%d ciphertext=%d", len(plain), len(envelope.Ciphertext))
			}
			_, got, err := OpenCatalog(raw, secret, time.Unix(1030, 0))
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("canonical content changed: %v", err)
			}
			// Build the previous uncompressed envelope only to measure its wire size.
			before := sealTestCatalogPayload(t, plain, secret, raw)
			t.Logf("services=%d envelope bytes: %d -> %d (%.1f%% smaller)", count, len(before), len(raw), 100*(1-float64(len(raw))/float64(len(before))))
		})
	}
}

func sealTestCatalogPayload(t testing.TB, payload, secret, template []byte) []byte {
	t.Helper()
	e, err := protocol.ParseCatalogEnvelope(template)
	if err != nil {
		t.Fatal(err)
	}
	key, ad, err := catalogParameters(secret, e)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	e.Ciphertext = aead.Seal(nil, e.Nonce, payload, ad)
	raw, err := protocol.EncodeCatalogEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func deflateTestPayload(t testing.TB, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteByte(1)
	w, err := flate.NewWriter(&b, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCatalogPayloadValidation(t *testing.T) {
	r, secret, plain := compressedFixture(t, 1)
	template, err := SealCatalog(r, secret)
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{"raw": append([]byte{0}, plain...), "deflate": deflateTestPayload(t, plain)} {
		t.Run(name, func(t *testing.T) {
			_, got, err := OpenCatalog(sealTestCatalogPayload(t, payload, secret, template), secret, time.Unix(1030, 0))
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("valid payload rejected: %v", err)
			}
		})
	}
	compressed := deflateTestPayload(t, plain)
	for name, payload := range map[string][]byte{
		"legacy": plain, "unknown": append([]byte{2}, plain...), "empty": {},
		"truncated": compressed[:len(compressed)-1], "corrupt": {1, 255, 255, 255},
		"trailing":  append(append([]byte{}, compressed...), 42),
		"expansion": deflateTestPayload(t, bytes.Repeat([]byte{'x'}, protocol.MaxControl+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := OpenCatalog(sealTestCatalogPayload(t, payload, secret, template), secret, time.Unix(1030, 0)); err == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
}

func TestCatalogPayloadBoundsAndFallback(t *testing.T) {
	random := make([]byte, 4096)
	_, _ = rand.New(rand.NewSource(42)).Read(random)
	payload, err := encodeCatalogPayload(random)
	if err != nil || len(payload) != len(random)+1 || payload[0] != 0 {
		t.Fatalf("incompressible fallback: %d %v", len(payload), err)
	}
	decoded, err := decodeCatalogPayload(payload)
	if err != nil || !bytes.Equal(decoded, random) {
		t.Fatalf("raw roundtrip: %v", err)
	}
	atLimit := bytes.Repeat([]byte{'x'}, protocol.MaxControl)
	for _, payload := range [][]byte{append([]byte{0}, atLimit...), deflateTestPayload(t, atLimit)} {
		decoded, err := decodeCatalogPayload(payload)
		if err != nil || !bytes.Equal(decoded, atLimit) {
			t.Fatalf("limit rejected: %v", err)
		}
	}
	oversized := append(atLimit, 'x')
	if _, err := encodeCatalogPayload(oversized); err == nil {
		t.Fatal("oversized input accepted")
	}
	if _, err := decodeCatalogPayload(append([]byte{0}, oversized...)); err == nil {
		t.Fatal("oversized raw payload accepted")
	}
}

func BenchmarkCatalogCompression(b *testing.B) {
	for _, count := range []int{1, 25, 100, 256} {
		r, secret, _ := compressedFixture(b, count)
		raw, err := SealCatalog(r, secret)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("services%d/seal", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := SealCatalog(r, secret); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("services%d/open", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := OpenCatalog(raw, secret, time.Unix(1030, 0)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
