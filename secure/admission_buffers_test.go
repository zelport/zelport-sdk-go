package secure

import (
	"bytes"
	"encoding/binary"
	"github.com/zelport/zelport-sdk-go/protocol"
	"io"
	"net"
	"testing"
)

// Keep the real admission handshake/cipher state, but capture transport records
// synchronously to check framing independently of socket scheduling.
type admissionWire struct {
	net.Conn
	bytes.Buffer
	calls int
	limit int
	zero  bool
}

func (w *admissionWire) Write(p []byte) (int, error) {
	w.calls++
	if w.zero {
		return 0, nil
	}
	if w.limit > 0 && len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}
func (w *admissionWire) Read(p []byte) (int, error) { return w.Buffer.Read(p) }

func admissionCapture(t *testing.T) (*Conn, *Conn, *admissionWire) {
	t.Helper()
	a, b, err := pair(t, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	sender, receiver := a.(*Conn), b.(*Conn)
	wire := &admissionWire{Conn: sender.Conn}
	sender.Conn = wire
	receiver.Conn = &admissionWire{Conn: receiver.Conn}
	return sender, receiver, wire
}
func TestAdmissionSingleWritePerRecord(t *testing.T) {
	sender, receiver, wire := admissionCapture(t)
	payload := bytes.Repeat([]byte{42}, 32768+7)
	if n, err := sender.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: %d %v", n, err)
	}
	if wire.calls != 2 {
		t.Fatalf("got %d transport writes for two records; want 2", wire.calls)
	}
	raw := wire.Bytes()
	if binary.BigEndian.Uint32(raw[:4]) != 32768+16 {
		t.Fatal("invalid first record length")
	}
	receiver.Conn.(*admissionWire).Buffer.Write(raw)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("payload changed")
	}
}
func TestAdmissionShortWrites(t *testing.T) {
	sender, receiver, wire := admissionCapture(t)
	wire.limit = 3
	payload := []byte("short writes must preserve the complete record")
	if n, err := sender.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: %d %v", n, err)
	}
	receiver.Conn.(*admissionWire).Buffer.Write(wire.Bytes())
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("payload changed")
	}
}
func TestAdmissionZeroWrite(t *testing.T) {
	sender, _, wire := admissionCapture(t)
	wire.zero = true
	if n, err := sender.Write([]byte("data")); n != 0 || err != io.ErrShortWrite {
		t.Fatalf("write: %d %v", n, err)
	}
}

func TestAdmissionReuseWithPartialReads(t *testing.T) {
	sender, receiver, wire := admissionCapture(t)
	input := receiver.Conn.(*admissionWire)
	payload := bytes.Repeat([]byte{19}, 32768)
	got := make([]byte, len(payload))
	// Warm maximum-size records. Subsequent requests should not allocate record
	// storage again, while small reads must retain the unread plaintext correctly.
	exchange := func() {
		wire.Reset()
		input.Reset()
		payload[0]++
		payload[len(payload)-1]++
		if _, err := sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		input.Buffer.Write(wire.Bytes())
		for offset := 0; offset < len(got); {
			end := min(offset+113, len(got))
			n, err := receiver.Read(got[offset:end])
			if err != nil {
				t.Fatal(err)
			}
			offset += n
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("partial read corrupted plaintext")
		}
	}
	exchange()
	allocations := testing.AllocsPerRun(100, exchange)
	if allocations > 4 {
		t.Fatalf("warm record exchange allocates %.0f times; budget is 4", allocations)
	}
}

func TestAdmissionRejectsInvalidRecordLengths(t *testing.T) {
	for _, length := range []uint32{0, 16, 32768 + 17, 1 << 31} {
		_, receiver, _ := admissionCapture(t)
		input := receiver.Conn.(*admissionWire)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], length)
		input.Buffer.Write(header[:])
		if length == 16 {
			input.Buffer.Write(make([]byte, 16))
		}
		if n, err := receiver.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("accepted length %d: %d %v", length, n, err)
		}
	}
}

// The optimization changes transport write boundaries, not the wire format.
func TestAdmissionExistingFramingInteroperability(t *testing.T) {
	sender, receiver, wire := admissionCapture(t)
	payload := []byte("unchanged admission wire format")
	if _, err := sender.Write(payload); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := protocol.ReadFrame(wire, 32768+16)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := receiver.rx.Decrypt(nil, nil, ciphertext)
	if err != nil || !bytes.Equal(plaintext, payload) {
		t.Fatalf("existing reader: %v", err)
	}

	ciphertext, err = sender.tx.Encrypt(nil, nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	input := receiver.Conn.(*admissionWire)
	if err := protocol.WriteFrame(input, ciphertext, 32768+16); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("existing writer payload changed")
	}
}
