package secure

import (
	"encoding/binary"
	"errors"
)

const (
	peerData byte = iota + 1
	peerCredit
	peerRenewRequest
	peerHS1
	peerHS2
	peerHS3
	peerFinish
	peerWindow   = 256 << 10
	peerMaxPlain = 32768
)

type peerFrame struct {
	kind byte
	body []byte
}

func (f peerFrame) bytes() ([]byte, error) {
	if f.kind < peerData || f.kind > peerFinish || len(f.body)+1 > peerMaxPlain || (f.kind != peerData && len(f.body)+1 > 4096) {
		return nil, errors.New("invalid peer record")
	}
	return append([]byte{f.kind}, f.body...), nil
}
func parsePeerFrame(b []byte) (peerFrame, error) {
	if len(b) < 1 {
		return peerFrame{}, errors.New("empty peer record")
	}
	f := peerFrame{b[0], b[1:]}
	_, e := f.bytes()
	return f, e
}
func epochBytes(epoch uint64) []byte { return binary.BigEndian.AppendUint64(nil, epoch) }
