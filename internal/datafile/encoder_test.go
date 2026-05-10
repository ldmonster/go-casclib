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
	"strings"
	"testing"
)

func TestEncodeRoundTripRaw(t *testing.T) {
	content := []byte("hello, casc world — the quick brown fox jumps over the lazy dog")

	blte, ckey, ekey, err := Encode(content, EncodeOptions{Mode: EncodeRaw, FrameSize: 16})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if ckey != md5.Sum(content) {
		t.Fatalf("ckey mismatch")
	}

	if ekey != md5.Sum(blte) {
		t.Fatalf("ekey mismatch")
	}

	if binary.LittleEndian.Uint32(blte[:4]) != 0x45544C42 {
		t.Fatalf("missing BLTE signature")
	}

	hdr, err := ParseHeader(blte)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	dec := &FrameDecoder{VerifyHashes: true}

	var got bytes.Buffer

	cursor := hdr.DataOffset
	for _, fr := range hdr.Frames {
		end := cursor + int(fr.EncodedSize)

		out, err := dec.Decode(fr, blte[cursor:end])
		if err != nil {
			t.Fatalf("Decode frame %d: %v", fr.Index, err)
		}

		got.Write(out)
		cursor = end
	}

	if !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("roundtrip mismatch:\n got=%q\nwant=%q", got.Bytes(), content)
	}
}

func TestEncodeRoundTripZlib(t *testing.T) {
	content := []byte(strings.Repeat("ABCDEFGH", 4096))

	blte, _, _, err := Encode(content, EncodeOptions{Mode: EncodeZlib, FrameSize: 4096})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Compressible data should be smaller than the raw input.
	if len(blte) >= len(content) {
		t.Fatalf("zlib failed to compress: encoded=%d content=%d", len(blte), len(content))
	}

	hdr, err := ParseHeader(blte)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	if hdr.FrameCount < 2 {
		t.Fatalf("expected multiple frames, got %d", hdr.FrameCount)
	}

	dec := &FrameDecoder{VerifyHashes: true}

	var got bytes.Buffer

	cursor := hdr.DataOffset
	for _, fr := range hdr.Frames {
		end := cursor + int(fr.EncodedSize)

		out, err := dec.Decode(fr, blte[cursor:end])
		if err != nil {
			t.Fatalf("Decode frame %d: %v", fr.Index, err)
		}

		got.Write(out)
		cursor = end
	}

	if !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestEncodeSingleFrameNoHeader(t *testing.T) {
	content := []byte("single frame body")

	blte, _, _, err := Encode(content, EncodeOptions{
		Mode:                EncodeRaw,
		SingleFrameNoHeader: true,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	hdr, err := ParseHeader(blte)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	if hdr.HeaderSize != 0 || hdr.FrameCount != 1 {
		t.Fatalf("expected HeaderSize=0 FrameCount=1, got %+v", hdr)
	}

	fr := hdr.Frames[0]
	fr.EncodedSize = uint32(len(blte) - hdr.DataOffset)

	dec := &FrameDecoder{VerifyHashes: false}

	out, err := dec.Decode(fr, blte[hdr.DataOffset:])
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if !bytes.Equal(out, content) {
		t.Fatalf("mismatch: %q", out)
	}
}

func TestEncodeEmpty(t *testing.T) {
	blte, _, _, err := Encode(nil, EncodeOptions{Mode: EncodeRaw})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	hdr, err := ParseHeader(blte)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	if hdr.FrameCount != 1 {
		t.Fatalf("expected 1 frame, got %d", hdr.FrameCount)
	}
}

func TestEncodeUnsupportedMode(t *testing.T) {
	if _, _, _, err := Encode([]byte("x"), EncodeOptions{Mode: EncodeMode('Q')}); err == nil {
		t.Fatalf("expected error for unsupported mode")
	}
}
