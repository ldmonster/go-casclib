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

package archive

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/decrypt"
	"github.com/ldmonster/go-casclib/internal/index"
)

// buildEncodedSpan constructs a BLTE_ENCODED_HEADER + minimal single-'N'-frame
// BLTE stream containing payload.
func buildEncodedSpan(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded := append([]byte{'N'}, payload...)
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
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	blte.Write(enc)
	blte.Write(cont)
	blte.Write(hash[:])
	blte.Write(encoded)

	// 30-byte encoded header (zeros are tolerated -- only 'BLTE' signature
	// after the header is checked).
	var span bytes.Buffer
	span.Write(make([]byte, EncodedHeaderSize))
	span.Write(blte.Bytes())
	return span.Bytes()
}

func TestDecodeSpanBareBLTE(t *testing.T) {
	span := buildEncodedSpan(t, []byte("hello"))
	// Strip the encoded header to test bare-BLTE path.
	out, err := DecodeSpan(span[EncodedHeaderSize:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Errorf("got %q", out)
	}
}

func TestDecodeSpanWithEncodedHeader(t *testing.T) {
	span := buildEncodedSpan(t, []byte("hello world"))
	out, err := DecodeSpan(span, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello world" {
		t.Errorf("got %q", out)
	}
}

func TestPoolReadSpan(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("the quick brown fox jumps over the lazy dog")
	span := buildEncodedSpan(t, payload)

	// Write some leading padding so we exercise non-zero ArchiveOffs.
	const off = 0x100
	body := make([]byte, off+len(span))
	copy(body[off:], span)

	if err := os.WriteFile(filepath.Join(dir, "data.005"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	pool := NewPool(dir)
	defer pool.Close()

	entry := index.EKeyEntry{
		ArchiveIndex: 5,
		ArchiveOffs:  off,
		EncodedSize:  uint32(len(span)),
	}
	out, err := pool.ReadSpan(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Errorf("payload mismatch: got %q", out)
	}
}

func TestPoolMissingFile(t *testing.T) {
	pool := NewPool(t.TempDir())
	defer pool.Close()
	_, err := pool.ReadSpan(index.EKeyEntry{ArchiveIndex: 0, EncodedSize: 64}, nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestStripEncodedHeader(t *testing.T) {
	// Bare BLTE — passthrough.
	bare := []byte{'B', 'L', 'T', 'E', 0, 0, 0, 0}
	out, err := stripEncodedHeader(bare)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, bare) {
		t.Errorf("bare passthrough failed")
	}

	// Wrapped — strips header.
	wrapped := append(make([]byte, EncodedHeaderSize), bare...)
	out, err = stripEncodedHeader(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, bare) {
		t.Errorf("wrapped strip failed")
	}

	// Bad signature anywhere — error.
	if _, err := stripEncodedHeader(make([]byte, EncodedHeaderSize+8)); err == nil {
		t.Errorf("expected error on bad signature")
	}
}

// buildEncryptedFrameBody returns a wire-format 'E' frame body (without the
// leading 'E' mode byte) referencing an unregistered key.
func buildEncryptedFrameBody(payloadLen int) []byte {
	var b bytes.Buffer
	b.WriteByte(8) // keyNameSize
	kn := make([]byte, 8)
	binary.LittleEndian.PutUint64(kn, 0xDEADBEEFCAFE0001) // not registered
	b.Write(kn)
	b.WriteByte(8) // ivSize
	b.Write(bytes.Repeat([]byte{0xAB}, 8))
	b.WriteByte('S')
	b.Write(bytes.Repeat([]byte{0x42}, payloadLen))
	return b.Bytes()
}

// buildTwoFrameBLTE builds a BLTE blob with one 'N' frame and one 'E'
// frame (unknown key). Returns the blob plus the two frames' content sizes.
func buildTwoFrameBLTE(t *testing.T, plain []byte, encContentLen int) []byte {
	t.Helper()

	nEncoded := append([]byte{'N'}, plain...)
	nHash := md5.Sum(nEncoded)

	eBody := buildEncryptedFrameBody(encContentLen)
	eEncoded := append([]byte{'E'}, eBody...)
	eHash := md5.Sum(eEncoded)

	const frameHdrSize = 24
	headerSize := uint32(12 + 2*frameHdrSize)

	var blte bytes.Buffer
	blte.Write([]byte{'B', 'L', 'T', 'E'})
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	blte.Write(hs)
	blte.WriteByte(0x0F)
	blte.Write([]byte{0, 0, 2}) // frame count = 2

	// Frame entries (encoded size, content size, hash).
	writeFrame := func(enc, cont uint32, h [16]byte) {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, enc)
		blte.Write(buf)
		binary.BigEndian.PutUint32(buf, cont)
		blte.Write(buf)
		blte.Write(h[:])
	}

	writeFrame(uint32(len(nEncoded)), uint32(len(plain)), nHash)
	writeFrame(uint32(len(eEncoded)), uint32(encContentLen), eHash)

	blte.Write(nEncoded)
	blte.Write(eEncoded)

	return blte.Bytes()
}

// TestOvercomeEncrypted is the M9 parity check for CASC_OVERCOME_ENCRYPTED:
// when an encrypted frame's key is missing from the registry, the option
// substitutes a zero-filled buffer of the frame's declared content size and
// the overall decode succeeds. Without the option the same input surfaces
// ErrEncrypted.
func TestOvercomeEncrypted(t *testing.T) {
	plain := []byte("alpha")
	const encContentLen = 7

	span := buildTwoFrameBLTE(t, plain, encContentLen)

	keys := decrypt.NewKeyRegistry()

	// Default behaviour: missing key surfaces as ErrEncrypted.
	if _, err := DecodeSpan(span, keys); !errors.Is(err, casc.ErrEncrypted) {
		t.Fatalf("DecodeSpan = %v, want ErrEncrypted", err)
	}

	// With OvercomeEncrypted: succeeds; encrypted frame is zero-filled.
	out, err := DecodeSpanWithOptions(span, keys, DecodeOptions{OvercomeEncrypted: true})
	if err != nil {
		t.Fatalf("DecodeSpanWithOptions: %v", err)
	}

	want := append([]byte{}, plain...)
	want = append(want, make([]byte, encContentLen)...)

	if !bytes.Equal(out, want) {
		t.Errorf("OvercomeEncrypted output mismatch:\n got %x\nwant %x", out, want)
	}
}
