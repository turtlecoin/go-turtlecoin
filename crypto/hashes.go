package crypto

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

type Hash struct {
	data [32]byte
}

func NewHash() *Hash {
	return &Hash{}
}

func (h *Hash) Bytes() []byte {
	return h.data[:]
}

func (h *Hash) Equal(a *Hash) int {
	sa, sh := a.Bytes(), h.Bytes()
	return subtle.ConstantTimeCompare(sa, sh)
}

func (h *Hash) SetBytes(x []byte) (*Hash, error) {
	if len(x) != 32 {
		return nil, errors.New("crypto/Hash: invalid hash encoding length")
	}

	copy(h.data[:], x)
	return h, nil
}

func (h *Hash) Size() int {
	return len(h.data)
}

func (h *Hash) String() string {
	return hex.EncodeToString(h.data[:])
}
