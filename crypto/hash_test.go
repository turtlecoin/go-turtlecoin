package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var input = []byte{
	0xcf, 0xc7, 0x65, 0xd9, 0x05, 0xc6, 0x5e, 0x2b, 0x61, 0x81, 0x6d,
	0xc1, 0xf0, 0xfd, 0x69, 0xf6, 0xf6, 0x77, 0x9f, 0x36, 0xed, 0x62,
	0x39, 0xac, 0x7e, 0x21, 0xff, 0x51, 0xef, 0x2c, 0x89, 0x1e}

var sha3hash = []byte{
	0x97, 0x45, 0x06, 0x60, 0x1a, 0x60, 0xdc, 0x46, 0x5e, 0x6e, 0x9a,
	0xcd, 0xdb, 0x56, 0x38, 0x89, 0xe6, 0x34, 0x71, 0x84, 0x9e, 0xc4,
	0x19, 0x86, 0x56, 0x55, 0x03, 0x54, 0xb8, 0x54, 0x1f, 0xcb}

const (
	sha3slow0    = "974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb"
	sha3slow4096 = "c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c"
	argon2i      = "debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a"
	argon2id     = "a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9"
)

func TestSHA3(t *testing.T) {
	actual := SHA3(input)
	if !bytes.Equal(sha3hash, actual.Bytes()) {
		t.Errorf("error computing sha3 hash\nInput: %s\nExpected: %s\nActual: %s", hex.EncodeToString(input), hex.EncodeToString(sha3hash), actual.String())
	}
}

func TestSHA3SlowHash(t *testing.T) {
	res0 := SHA3SlowHash(input, 0)
	if sha3slow0 != res0.String() {
		t.Errorf("error computing sha3 slow hash\nInput: %s\nExpected: %s\nActual: %s", hex.EncodeToString(input), sha3slow0, res0.String())
	}

	res4096 := SHA3SlowHash(input, 4096)
	if sha3slow4096 != res4096.String() {
		t.Errorf("error computing sha3 slow hash\nInput: %s\nExpected: %s\nActual: %s", hex.EncodeToString(input), sha3slow4096, res4096.String())
	}
}

func TestArgon2i(t *testing.T) {
	res := Argon2i(input, 4, 1024, 1)
	if argon2i != res.String() {
		t.Errorf("error computing argon2i hash\nInput: %s\nExpected: %s\nActual: %s", hex.EncodeToString(input), argon2i, res.String())
	}
}

func TestArgon2id(t *testing.T) {
	res := Argon2id(input, 4, 1024, 1)
	if argon2id != res.String() {
		t.Errorf("error computing argon2i hash\nInput: %s\nExpected: %s\nActual: %s", hex.EncodeToString(input), argon2id, res.String())
	}
}
