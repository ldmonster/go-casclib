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
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/internal/datafile"
)

func TestWriterRoundTrip(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(dir, 0)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	content := bytes.Repeat([]byte("the quick brown fox\n"), 256)

	blte, _, ekey, err := datafile.Encode(content, datafile.EncodeOptions{Mode: datafile.EncodeRaw})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	entry, err := w.WriteSpan(blte, ekey)
	if err != nil {
		t.Fatalf("WriteSpan: %v", err)
	}

	if entry.ArchiveIndex != 0 || entry.ArchiveOffs != 0 {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	if got := uint32(EncodedHeaderSize + len(blte)); entry.EncodedSize != got {
		t.Fatalf("EncodedSize=%d want=%d", entry.EncodedSize, got)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back the bytes and run them through DecodeSpan.
	data, err := os.ReadFile(filepath.Join(dir, "data.000"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	got, err := DecodeSpan(data[entry.ArchiveOffs:entry.ArchiveOffs+entry.EncodedSize], nil)
	if err != nil {
		t.Fatalf("DecodeSpan: %v", err)
	}

	if !bytes.Equal(got, content) {
		t.Fatalf("roundtrip mismatch")
	}

	// And via the Pool / ReadSpan pipeline.
	p := NewPool(dir)
	defer p.Close()

	got2, err := p.ReadSpan(entry, nil)
	if err != nil {
		t.Fatalf("ReadSpan: %v", err)
	}

	if !bytes.Equal(got2, content) {
		t.Fatalf("ReadSpan mismatch")
	}

	// Verify the byte-reversed EKey field of the encoded header matches.
	hdr := data[entry.ArchiveOffs : entry.ArchiveOffs+EncodedHeaderSize]

	var reversed [16]byte
	for i := 0; i < 16; i++ {
		reversed[i] = hdr[15-i]
	}

	if reversed != ekey {
		t.Fatalf("encoded-header EKey mismatch: got %x want %x", reversed, ekey)
	}
}

func TestWriterSegmentRollover(t *testing.T) {
	dir := t.TempDir()

	// Tiny segment cap so two spans land in different files.
	w, err := NewWriter(dir, 1024)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	span1 := bytes.Repeat([]byte{0x41}, 600)
	span2 := bytes.Repeat([]byte{0x42}, 600)

	blte1, _, ek1, _ := datafile.Encode(span1, datafile.EncodeOptions{Mode: datafile.EncodeRaw})
	blte2, _, ek2, _ := datafile.Encode(span2, datafile.EncodeOptions{Mode: datafile.EncodeRaw})

	e1, err := w.WriteSpan(blte1, ek1)
	if err != nil {
		t.Fatalf("WriteSpan #1: %v", err)
	}

	e2, err := w.WriteSpan(blte2, ek2)
	if err != nil {
		t.Fatalf("WriteSpan #2: %v", err)
	}

	if e1.ArchiveIndex == e2.ArchiveIndex {
		t.Fatalf("expected separate archives, got %d/%d", e1.ArchiveIndex, e2.ArchiveIndex)
	}

	if _, err := os.Stat(filepath.Join(dir, "data.001")); err != nil {
		t.Fatalf("data.001 should exist: %v", err)
	}
}

func TestWriterMD5OfFullEncoded(t *testing.T) {
	// Sanity: BLTE-ekey is MD5 of the BLTE bytes (not of the encoded
	// header + BLTE). The encoded-header EKey field is the same MD5
	// stored byte-reversed.
	content := []byte("hello")

	blte, _, ekey, err := datafile.Encode(content, datafile.EncodeOptions{Mode: datafile.EncodeRaw})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if md5.Sum(blte) != ekey {
		t.Fatalf("ekey is not MD5(blte)")
	}
}
