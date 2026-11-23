package encryption

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

func parsePSKCipher(name string) (aes bool, lnt int, err error) {
	switch name {
	case "aes-128-gcm":
		return true, 16, nil
	case "aes-256-gcm":
		return true, 32, nil
	case "chacha20-poly1305":
		return false, 32, nil
	}
	return false, 0, errors.New("unknown VLESS PSK cipher: " + name)
}

type SymmetricClient struct {
	Key []byte
	AES bool
	Len int
}

func NewSymmetricClient(cipher string, psk []byte) (*SymmetricClient, error) {
	aes, lnt, err := parsePSKCipher(cipher)
	if err != nil {
		return nil, err
	}
	if len(psk) == 0 {
		return nil, errors.New("empty VLESS PSK")
	}
	return &SymmetricClient{Key: psk, AES: aes, Len: lnt}, nil
}

func (s *SymmetricClient) Handshake(conn net.Conn) (*CommonConn, error) {
	c := NewCommonConn(conn, s.AES)
	c.KeyLen = s.Len
	c.UnitedKey = s.Key

	salt := make([]byte, s.Len)
	rand.Read(salt)

	preludeAEAD := NewAEAD(salt, s.Key, s.AES, s.Len)
	ts := make([]byte, 4)
	binary.BigEndian.PutUint32(ts, uint32(time.Now().Unix()))
	sTs := preludeAEAD.Seal(nil, nil, ts, nil)

	c.AEAD = NewAEAD(sTs, s.Key, s.AES, s.Len)
	c.Salt = salt

	c.PreWrite = append(append(make([]byte, 0, s.Len+20), salt...), sTs...)
	return c, nil
}
