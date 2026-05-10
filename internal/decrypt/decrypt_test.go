// Copyright 2026 go-casclib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package decrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// Salsa20 self-consistency: encrypt, then decrypt, gives plaintext. Salsa20
// is a stream cipher, so encryption == decryption.
func TestSalsa20RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xA5}, 16)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	plain := []byte("the quick brown fox jumps over the lazy dog!!")
	cipher := make([]byte, len(plain))
	salsa20XOR(cipher, plain, key, nonce)
	if bytes.Equal(cipher, plain) {
		t.Fatalf("salsa20 produced identical bytes")
	}
	dec := make([]byte, len(plain))
	salsa20XOR(dec, cipher, key, nonce)
	if !bytes.Equal(dec, plain) {
		t.Errorf("salsa20 roundtrip failed")
	}
}

// Salsa20-128 known answer test from the eSTREAM test vectors.
// Key = 80000000000000000000000000000000, IV = 0000000000000000.
// First 64 bytes of keystream (XOR of all-zero plaintext):
//
//	4DFA5E481DA23EA09A31022050859936
//	DA52FCEE218005164F267CB65F5CFD7F
//	2B4F97E0FF16924A52DF269515110A07
//	F9E460BC65EF95DA58F740B7D1DBB0AA
func TestSalsa20KAT128(t *testing.T) {
	key := make([]byte, 16)
	key[0] = 0x80
	nonce := make([]byte, 8)
	plain := make([]byte, 64)
	cipher := make([]byte, 64)
	salsa20XOR(cipher, plain, key, nonce)
	want := []byte{
		0x4D, 0xFA, 0x5E, 0x48, 0x1D, 0xA2, 0x3E, 0xA0,
		0x9A, 0x31, 0x02, 0x20, 0x50, 0x85, 0x99, 0x36,
		0xDA, 0x52, 0xFC, 0xEE, 0x21, 0x80, 0x05, 0x16,
		0x4F, 0x26, 0x7C, 0xB6, 0x5F, 0x5C, 0xFD, 0x7F,
		0x2B, 0x4F, 0x97, 0xE0, 0xFF, 0x16, 0x92, 0x4A,
		0x52, 0xDF, 0x26, 0x95, 0x15, 0x11, 0x0A, 0x07,
		0xF9, 0xE4, 0x60, 0xBC, 0x65, 0xEF, 0x95, 0xDA,
		0x58, 0xF7, 0x40, 0xB7, 0xD1, 0xDB, 0xB0, 0xAA,
	}
	if !bytes.Equal(cipher, want) {
		t.Errorf("Salsa20-128 KAT mismatch:\n got %x\nwant %x", cipher, want)
	}
}

func TestKeyRegistry(t *testing.T) {
	r := NewKeyRegistry()
	if err := r.Add(0x1234, make([]byte, 8)); err == nil {
		t.Errorf("expected error for short key")
	}
	if err := r.Add(0x1234, make([]byte, 16)); err != nil {
		t.Errorf("Add: %v", err)
	}
	if r.Find(0x1234) == nil {
		t.Errorf("Find returned nil")
	}
	if r.Find(0xDEAD) != nil {
		t.Errorf("Find unknown should be nil")
	}
}

// TestDecryptFrameSalsa20 builds an encrypted-frame wire-format payload
// and verifies decryption.
func TestDecryptFrameSalsa20(t *testing.T) {
	r := NewKeyRegistry()
	keyName := uint64(0xCAFEBABEDEADBEEF)
	key := bytes.Repeat([]byte{0x42}, 16)
	if err := r.Add(keyName, key); err != nil {
		t.Fatal(err)
	}

	plain := []byte("decrypt-frame-test")
	frameIndex := 7

	// Wire format: [1] keyNameSize=8, [8] keyName LE, [1] ivSize=8, [8] iv,
	// [1] 'S', [N] ciphertext.
	iv := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	// XOR IV with frame index (must match decryption).
	xoredIV := make([]byte, 8)
	copy(xoredIV, iv)
	for i := 0; i < 4; i++ {
		xoredIV[i] ^= byte(frameIndex >> uint(i*8))
	}
	cipher := make([]byte, len(plain))
	salsa20XOR(cipher, plain, key, xoredIV)

	var buf bytes.Buffer
	buf.WriteByte(8)
	knBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(knBuf, keyName)
	buf.Write(knBuf)
	buf.WriteByte(8)
	buf.Write(iv)
	buf.WriteByte('S')
	buf.Write(cipher)

	got, err := r.DecryptFrame(buf.Bytes(), frameIndex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestDecryptFrameUnknownKey(t *testing.T) {
	r := NewKeyRegistry()
	wire := []byte{
		8, 1, 2, 3, 4, 5, 6, 7, 8, // keyName
		8, 0, 0, 0, 0, 0, 0, 0, 0, // iv
		'S',
		'X', 'Y', 'Z',
	}
	_, err := r.DecryptFrame(wire, 0)
	if err == nil || !errors.Is(err, casc.ErrEncrypted) {
		t.Errorf("expected ErrEncrypted, got %v", err)
	}
}
