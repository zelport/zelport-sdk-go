package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

func RandomNonce() string {
	v, e := Token()
	if e != nil {
		panic(e)
	}
	return v
}

type Hello struct {
	Version        int
	Purpose, Nonce string
}

func NewHello(p string) Hello { return Hello{Version, p, RandomNonce()} }
func (h Hello) Bytes() ([]byte, error) {
	if h.Version != Version || (h.Purpose != "control" && h.Purpose != "connect" && h.Purpose != "join") {
		return nil, errors.New("unsupported admission context")
	}
	if _, e := DecodeKey(h.Nonce); e != nil {
		return nil, e
	}
	return json.Marshal([]any{h.Version, h.Purpose, h.Nonce})
}
func ParseHello(b []byte) (Hello, error) {
	var h Hello
	e := Array(b, &h.Version, &h.Purpose, &h.Nonce)
	if e == nil {
		_, e = h.Bytes()
	}
	return h, e
}

type PeerContext struct {
	Version                                                      int
	Group, Consumer, Provider, ConsumerKey, ProviderKey, Session string
}

func (p PeerContext) Bytes() ([]byte, error) {
	if p.Version != Version || !ValidID(p.Consumer) || !ValidID(p.Provider) || p.Consumer == p.Provider || len(p.Group) != 64 {
		return nil, errors.New("invalid peer context")
	}
	for _, k := range []string{p.ConsumerKey, p.ProviderKey, p.Session} {
		if _, e := DecodeKey(k); e != nil {
			return nil, e
		}
	}
	return json.Marshal([]any{p.Version, p.Group, p.Consumer, p.Provider, p.ConsumerKey, p.ProviderKey, p.Session})
}
func Array(b []byte, fields ...any) error {
	var v []json.RawMessage
	if e := Decode(b, &v); e != nil {
		return e
	}
	if len(v) != len(fields) {
		return errors.New("invalid wire field count")
	}
	for i, f := range fields {
		if e := Decode(v[i], f); e != nil {
			return e
		}
	}
	return nil
}
func Decode(b []byte, v any) error {
	if len(b) > MaxSnapshot {
		return errors.New("message too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if e := scan(d, 0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func scan(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeded")
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	if t == nil {
		return errors.New("null wire field")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid key")
			}
			seen[key] = true
			if e = scan(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = scan(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return errors.New("invalid delimiter")
	}
	_, e = d.Token()
	return e
}
func WriteFrame(w io.Writer, b []byte, max int) error {
	if len(b) == 0 || len(b) > max {
		return errors.New("invalid frame length")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if e := writeAll(w, header[:]); e != nil {
		return e
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, errors.New("invalid frame length")
	}
	b := make([]byte, int(n))
	_, e := io.ReadFull(r, b)
	return b, e
}
func EncodeMessage(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	if len(b) == 0 || len(b) > MaxControl {
		return nil, errors.New("control message too large")
	}
	return b, nil
}
func WriteJSON(w io.Writer, v any) error {
	b, e := EncodeMessage(v)
	if e != nil {
		return e
	}
	return WriteFrame(w, b, MaxControl)
}
func ReadJSON(r io.Reader, v any) error {
	b, e := ReadFrame(r, MaxControl)
	if e != nil {
		return e
	}
	return Decode(b, v)
}
