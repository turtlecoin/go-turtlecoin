package crypto

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// Hash represents a 256-bit hash value.
type Hash struct {
	data [32]byte
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

// String returns the hex representation of hash value.
func (h *Hash) String() string {
	return hex.EncodeToString(h.data[:])
}

type buffer struct {
	base [32]byte
	idx  uint64
}

func (b *buffer) Bytes() []byte {
	res := &bytes.Buffer{}

	binary.Write(res, binary.LittleEndian, b)

	return res.Bytes()
}

// SHA3 hashes the given input into a 256-bit hash using SHA-3 algorithm.
func SHA3(input []byte) *Hash {
	return &Hash{sha3.Sum256(input)}
}

// SHA3SlowHash hashes the given POD using SHA-3 for the number of rounds
// indicated by iterations. This method also performs the basic key stretching
// whereby the input data is appended to the resulting hash each round to "salt"
// each round of hashing to prevent simply iterating the hash over itself.
func SHA3SlowHash(input []byte, iterations uint64) *Hash {
	result := sha3.Sum256(input)

	var buf buffer

	for i := uint64(0); i < iterations; i++ {
		buf.base = result
		buf.idx = i
		result = sha3.Sum256(buf.Bytes())
	}

	return &Hash{result}
}

func Argon2i(input []byte, iterations, memory uint32, threads uint8) *Hash {
	var result [32]byte

	copy(result[:], argon2.Key(input, input, iterations, memory, threads, 32))

	return &Hash{result}
}

func Argon2id(input []byte, iterations, memory uint32, threads uint8) *Hash {
	var result [32]byte

	copy(result[:], argon2.IDKey(input, input, iterations, memory, threads, 32))

	return &Hash{result}
}
