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

package datafile

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/compress"
	"github.com/ldmonster/go-casclib/internal/decrypt"
)

// salsa20XOR is unexported in decrypt; for this test we round-trip via the
// public DecryptFrame API by pre-encrypting through the same code path. We
// achieve that by building an encrypted frame whose plaintext is a 'Z' frame.

// TestEncryptedZlibPipeline: ENCRYPTED('S') -> 'Z' (zlib) -> "hello"
func TestEncryptedZlibPipeline(t *testing.T) {
	// Step 1: build the inner 'Z' (zlib) frame: 'Z' + zlib(payload).
	plain := []byte("hello CASC encrypted+compressed world!")
	zlibBytes, err := compress.Deflate(plain)
	if err != nil {
		t.Fatal(err)
	}
	innerZ := append([]byte{'Z'}, zlibBytes...)

	// Step 2: encrypt innerZ to produce ciphertext using the decrypt
	// package via a known wire format. We build the wire format manually
	// using a registered key and the internal encrypt path. Since we only
	// expose DecryptFrame, do the same Salsa20 stream in reverse: register
	// the key, build wire (no payload yet), determine IV used, then
	// produce ciphertext such that DecryptFrame yields innerZ.

	keyName := uint64(0x0123456789ABCDEF)
	key := bytes.Repeat([]byte{0x77}, 16)
	r := decrypt.NewKeyRegistry()
	if err := r.Add(keyName, key); err != nil {
		t.Fatal(err)
	}

	// Plaintext echo: round-trip through DecryptFrame twice (once to
	// "encrypt" since stream cipher is symmetric).
	frameIndex := 0
	iv := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	var wire bytes.Buffer
	wire.WriteByte(8)
	knBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(knBuf, keyName)
	wire.Write(knBuf)
	wire.WriteByte(8)
	wire.Write(iv)
	wire.WriteByte('S')
	// "Encrypt" by passing innerZ as ciphertext through DecryptFrame: since
	// Salsa20 is symmetric, decrypting plaintext gives ciphertext.
	wire.Write(innerZ)

	cipher, err := r.DecryptFrame(wire.Bytes(), frameIndex)
	if err != nil {
		t.Fatal(err)
	}
	// Build the actual encrypted-frame wire with cipher as the payload.
	var realWire bytes.Buffer
	realWire.WriteByte('E')
	realWire.WriteByte(8)
	realWire.Write(knBuf)
	realWire.WriteByte(8)
	realWire.Write(iv)
	realWire.WriteByte('S')
	realWire.Write(cipher)

	// Build a minimal BLTE wrapping this single 'E' frame.
	encoded := realWire.Bytes()
	hash := md5.Sum(encoded)
	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize
	var blte bytes.Buffer
	blte.Write([]byte{'B', 'L', 'T', 'E'})
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	blte.Write(hs)
	blte.WriteByte(0x0F)
	blte.Write([]byte{0, 0, 1})
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(plain)))
	blte.Write(enc)
	blte.Write(cont)
	blte.Write(hash[:])
	blte.Write(encoded)

	// Decode through the FrameDecoder.
	hdr, err := ParseHeader(blte.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	body := blte.Bytes()[hdr.DataOffset:]
	dec := &FrameDecoder{
		VerifyHashes: true,
		Decrypt: func(in []byte, idx int) ([]byte, error) {
			return r.DecryptFrame(in, idx)
		},
	}
	got, err := dec.Decode(hdr.Frames[0], body)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("pipeline mismatch:\n got %q\nwant %q", got, plain)
	}
}
