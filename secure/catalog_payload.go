package secure

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"

	"github.com/zelport/zelport-sdk-go/protocol"
)

// The encoding byte is authenticated inside the catalog AEAD envelope.
// Each record has an independent compression context; application traffic is unaffected.
const (
	catalogRaw byte = iota
	catalogDeflate
)

func encodeCatalogPayload(plain []byte) ([]byte, error) {
	if len(plain) > protocol.MaxControl {
		return nil, errors.New("catalog plaintext too large")
	}
	var b bytes.Buffer
	b.WriteByte(catalogDeflate)
	w, err := flate.NewWriter(&b, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(plain); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	if b.Len() < len(plain)+1 {
		return b.Bytes(), nil
	}
	return append([]byte{catalogRaw}, plain...), nil
}

// Decode only after AEAD authentication. Bound expansion before parsing JSON.
func decodeCatalogPayload(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty catalog payload")
	}
	switch payload[0] {
	case catalogRaw:
		if len(payload)-1 > protocol.MaxControl {
			return nil, errors.New("catalog plaintext too large")
		}
		return payload[1:], nil
	case catalogDeflate:
		// ByteReader prevents flate from reading past the end of its stream.
		source := bytes.NewReader(payload[1:])
		r := flate.NewReader(source)
		defer r.Close()
		plain, err := io.ReadAll(io.LimitReader(r, protocol.MaxControl+1))
		if err != nil {
			return nil, errors.New("invalid compressed catalog")
		}
		if len(plain) > protocol.MaxControl {
			return nil, errors.New("catalog plaintext too large")
		}
		if source.Len() != 0 {
			return nil, errors.New("trailing compressed catalog data")
		}
		return plain, nil
	default:
		return nil, errors.New("unsupported catalog payload encoding")
	}
}
