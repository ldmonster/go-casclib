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

package encoding

import (
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// buildSyntheticEncoding builds a minimal valid ENCODING file with one CKey
// page containing two entries.
func buildSyntheticEncoding(t *testing.T) []byte {
	t.Helper()
	const pageKB = 4
	const pageBytes = pageKB * 1024
	const especBlockSize = 0
	const cPageCount = 1
	const ePageCount = 0

	hdr := make([]byte, fileEncodingHeaderSize)
	binary.LittleEndian.PutUint16(hdr[0:2], casc.MagicEncoding)
	hdr[2] = 1
	hdr[3] = 16
	hdr[4] = 16
	binary.BigEndian.PutUint16(hdr[5:7], pageKB)
	binary.BigEndian.PutUint16(hdr[7:9], pageKB)
	binary.BigEndian.PutUint32(hdr[9:13], cPageCount)
	binary.BigEndian.PutUint32(hdr[13:17], ePageCount)
	hdr[17] = 0
	binary.BigEndian.PutUint32(hdr[18:22], especBlockSize)

	// Entry 1: 1 EKey
	makeEntry := func(seed byte, contentSize uint32, n int) []byte {
		buf := make([]byte, 6+16+n*16)
		binary.LittleEndian.PutUint16(buf[0:2], uint16(n))
		binary.BigEndian.PutUint32(buf[2:6], contentSize)
		for i := 0; i < 16; i++ {
			buf[6+i] = seed + byte(i)
		}
		for k := 0; k < n; k++ {
			for i := 0; i < 16; i++ {
				buf[6+16+k*16+i] = seed*7 + byte(k) + byte(i)
			}
		}
		return buf
	}
	page := make([]byte, pageBytes)
	off := 0
	e1 := makeEntry(0x10, 0x12345, 1)
	copy(page[off:], e1)
	off += len(e1)
	e2 := makeEntry(0x20, 0x67890, 2)
	copy(page[off:], e2)
	off += len(e2)

	// CKey page index entries: 1 page * (16+16) bytes; we just zero them.
	cKeyPageIndex := make([]byte, cPageCount*32)

	out := make([]byte, 0)
	out = append(out, hdr...)
	out = append(out, cKeyPageIndex...)
	out = append(out, page...)
	return out
}

func TestParseEncoding(t *testing.T) {
	data := buildSyntheticEncoding(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Header.CKeyPageCount != 1 {
		t.Errorf("page count = %d", f.Header.CKeyPageCount)
	}
	if len(f.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(f.Entries))
	}
	var ck casc.CKey
	for i := 0; i < 16; i++ {
		ck[i] = 0x10 + byte(i)
	}
	e := f.Find(ck)
	if e == nil {
		t.Fatal("entry not found")
	}
	if e.ContentSize != 0x12345 {
		t.Errorf("content size = %#x", e.ContentSize)
	}
	if len(e.EKeys) != 1 {
		t.Errorf("ekeys = %d", len(e.EKeys))
	}
}

func TestParseEncodingBadMagic(t *testing.T) {
	data := make([]byte, fileEncodingHeaderSize)
	if _, err := Parse(data); err == nil {
		t.Errorf("expected error")
	}
}
