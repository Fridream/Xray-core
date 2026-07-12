package encryption

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
)

type SymmetricServer struct {
	Key []byte
	AES bool
	Len int
	flt *filter
}

func NewSymmetricServer(cipher string, psk []byte) (*SymmetricServer, error) {
	aes, lnt, err := parsePSKCipher(cipher)
	if err != nil {
		return nil, err
	}
	if len(psk) == 0 {
		return nil, errors.New("empty VLESS PSK")
	}
	return &SymmetricServer{Key: psk, AES: aes, Len: lnt, flt: newFilter()}, nil
}

func (s *SymmetricServer) Handshake(conn net.Conn, fallback *[]byte) (*CommonConn, error) {
	c := NewCommonConn(conn, s.AES)
	c.KeyLen = s.Len
	c.UnitedKey = s.Key

	head := make([]byte, s.Len+20)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, head...)
	}
	saltC := head[:s.Len]
	sTs := head[s.Len:]

	preludeAEAD := NewAEAD(saltC, s.Key, s.AES, s.Len)
	ts := make([]byte, 4)
	if _, err := preludeAEAD.Open(ts[:0], nil, sTs, nil); err != nil {
		return nil, s.reject(conn, fallback, "authentication failed")
	}
	now := time.Now().Unix()
	if t := int64(binary.BigEndian.Uint32(ts)); t < now-30 || t > now+30 {
		return nil, s.reject(conn, fallback, "stale timestamp")
	}
	if !s.flt.checkAndAdd(saltC, now) {
		return nil, s.reject(conn, fallback, "replay detected")
	}
	if fallback != nil {
		*fallback = nil
	}

	c.PeerAEAD = NewAEAD(sTs, s.Key, s.AES, s.Len)
	saltS := make([]byte, s.Len)
	rand.Read(saltS)
	saltM := append(append(make([]byte, 0, s.Len*2), saltS...), saltC...)
	c.AEAD = NewAEAD(saltM, s.Key, s.AES, s.Len)
	c.PreWrite = saltS
	return c, nil
}

func (s *SymmetricServer) reject(conn net.Conn, fallback *[]byte, reason string) error {
	if fallback == nil {
		noises := make([]byte, crypto.RandBetween(1279, 2279))
		var err error
		for err == nil {
			rand.Read(noises)
			_, err = DecodeHeader(noises)
		}
		conn.Write(noises)
	}
	return errors.New("VLESS PSK: " + reason)
}

type filter struct {
	mutx sync.Mutex
	curr map[string]struct{}
	prev map[string]struct{}
	last int64
}

func newFilter() *filter {
	return &filter{}
}

func (f *filter) checkAndAdd(key []byte, now int64) bool {
	k := string(key)
	f.mutx.Lock()
	defer f.mutx.Unlock()
	if now-f.last >= 60 {
		f.prev = f.curr
		f.curr = make(map[string]struct{})
		f.last = now
	}
	if _, ok := f.curr[k]; ok {
		return false
	}
	if _, ok := f.prev[k]; ok {
		return false
	}
	f.curr[k] = struct{}{}
	return true
}
