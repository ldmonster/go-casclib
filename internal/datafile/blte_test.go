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

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/compress"
)

// build a BLTE file with a single 'N' frame.
func buildSingleNormalBLTE(payload []byte) []byte {
	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize
	encoded := append([]byte{'N'}, payload...)
	hash := md5.Sum(encoded)

	buf := make([]byte, 0, headerSize+len(encoded))
	buf = append(buf, 'B', 'L', 'T', 'E')
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	buf = append(buf, hs...)
	buf = append(buf, 0x0F)
	buf = append(buf, 0, 0, 1) // frame count = 1
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	buf = append(buf, enc...)
	buf = append(buf, cont...)
	buf = append(buf, hash[:]...)
	buf = append(buf, encoded...)
	return buf
}

// build a BLTE file with a single 'Z' (zlib) frame.
func buildSingleZlibBLTE(t *testing.T, payload []byte) []byte {
	t.Helper()
	zlibBytes, err := compress.Deflate(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte{'Z'}, zlibBytes...)
	hash := md5.Sum(encoded)

	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize

	buf := make([]byte, 0, headerSize+len(encoded))
	buf = append(buf, 'B', 'L', 'T', 'E')
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	buf = append(buf, hs...)
	buf = append(buf, 0x0F)
	buf = append(buf, 0, 0, 1)
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	buf = append(buf, enc...)
	buf = append(buf, cont...)
	buf = append(buf, hash[:]...)
	buf = append(buf, encoded...)
	return buf
}

func TestParseHeaderSingleFrame(t *testing.T) {
	data := buildSingleNormalBLTE([]byte("hello"))
	hdr, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.FrameCount != 1 {
		t.Fatalf("frame count = %d", hdr.FrameCount)
	}
	if hdr.Frames[0].EncodedSize != 6 {
		t.Errorf("enc size = %d", hdr.Frames[0].EncodedSize)
	}
	if hdr.Frames[0].ContentSize != 5 {
		t.Errorf("content size = %d", hdr.Frames[0].ContentSize)
	}
}

func TestParseHeaderInvalidSig(t *testing.T) {
	if _, err := ParseHeader([]byte("XXXX\x00\x00\x00\x00")); err == nil {
		t.Errorf("expected error")
	}
}

func TestParseHeaderHeaderlessSingleFrame(t *testing.T) {
	data := []byte{'B', 'L', 'T', 'E', 0, 0, 0, 0, 'X', 'Y'}
	hdr, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.HeaderSize != 0 || hdr.FrameCount != 1 || hdr.DataOffset != 8 {
		t.Errorf("unexpected header: %+v", hdr)
	}
}

func TestDecodeNormal(t *testing.T) {
	want := []byte("hello world")
	data := buildSingleNormalBLTE(want)
	hdr, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	dec := &FrameDecoder{VerifyHashes: true}
	body := data[hdr.DataOffset : hdr.DataOffset+int(hdr.Frames[0].EncodedSize)]
	got, err := dec.Decode(hdr.Frames[0], body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDecodeZlib(t *testing.T) {
	want := bytes.Repeat([]byte("abcdef "), 200)
	data := buildSingleZlibBLTE(t, want)
	hdr, err := ParseHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	dec := &FrameDecoder{VerifyHashes: true}
	body := data[hdr.DataOffset : hdr.DataOffset+int(hdr.Frames[0].EncodedSize)]
	got, err := dec.Decode(hdr.Frames[0], body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("zlib decode mismatch")
	}
}

func TestDecodeEncryptedNoCallback(t *testing.T) {
	dec := &FrameDecoder{}
	_, err := dec.Decode(Frame{}, []byte{'E', 1, 2, 3})
	if err == nil || !errorsIs(err, casc.ErrEncrypted) {
		t.Errorf("expected ErrEncrypted, got %v", err)
	}
}

// errorsIs unwraps without importing errors twice.
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
