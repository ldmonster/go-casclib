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

package cdn

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// makeArchiveIndex builds a footer-hash-valid archive-index blob with the
// given entries, using PageSizeKB=4, OffsetBytes=4, SizeBytes=4, EKeyLength=16.
func makeArchiveIndex(entries []ArchiveIndexEntry) []byte {
	footer := ArchiveIndexFooter{
		PageSizeKB:      4,
		OffsetBytes:     4,
		SizeBytes:       4,
		EKeyLength:      16,
		FooterHashBytes: 8,
	}
	return EncodeArchiveIndex(footer, entries)
}

func ekey(b byte) (e casc.EKey) {
	for i := range e {
		e[i] = b
	}
	return
}

func TestParseArchiveIndex_RoundTrip(t *testing.T) {
	entries := []ArchiveIndexEntry{
		{EKey: ekey(0x11), Offset: 0, EncodedSize: 100},
		{EKey: ekey(0x22), Offset: 100, EncodedSize: 250},
		{EKey: ekey(0x33), Offset: 350, EncodedSize: 1024},
	}
	blob := makeArchiveIndex(entries)
	got, err := ParseArchiveIndex(blob)
	if err != nil {
		t.Fatalf("ParseArchiveIndex: %v", err)
	}
	if got.Footer.ElementCount != uint32(len(entries)) {
		t.Fatalf("element count %d want %d", got.Footer.ElementCount, len(entries))
	}
	if got.Footer.PageLength != 4096 || got.Footer.ItemLength != 24 {
		t.Fatalf("derived sizes wrong: page=%d item=%d", got.Footer.PageLength, got.Footer.ItemLength)
	}
	if len(got.Entries) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got.Entries), len(entries))
	}
	for i, e := range entries {
		if got.Entries[i] != e {
			t.Fatalf("entry %d mismatch:\n got=%+v\nwant=%+v", i, got.Entries[i], e)
		}
	}
}

func TestParseArchiveIndex_MultiPage(t *testing.T) {
	// 4KB page / 24 bytes per item = 170 items per page; force 3 pages.
	const itemsPerPage = 4096 / 24
	entries := make([]ArchiveIndexEntry, itemsPerPage*2+5)
	for i := range entries {
		var ek casc.EKey
		ek[0] = byte(i >> 8)
		ek[1] = byte(i)
		ek[15] = 0xAA
		entries[i] = ArchiveIndexEntry{
			EKey:        ek,
			Offset:      uint64(i) * 13,
			EncodedSize: uint64(i) + 1,
		}
	}
	blob := makeArchiveIndex(entries)
	got, err := ParseArchiveIndex(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Entries) != len(entries) {
		t.Fatalf("entry count %d != %d", len(got.Entries), len(entries))
	}
	if got.Entries[len(entries)-1] != entries[len(entries)-1] {
		t.Fatal("last entry mismatch")
	}
}

func TestParseArchiveIndex_RejectsTruncated(t *testing.T) {
	if _, err := ParseArchiveIndex(nil); !errors.Is(err, casc.ErrBadFormat) {
		t.Fatalf("nil: want ErrBadFormat, got %v", err)
	}
	if _, err := ParseArchiveIndex(make([]byte, 10)); !errors.Is(err, casc.ErrBadFormat) {
		t.Fatalf("short: want ErrBadFormat, got %v", err)
	}
}

func TestParseArchiveIndex_RejectsBadFooter(t *testing.T) {
	entries := []ArchiveIndexEntry{{EKey: ekey(1), Offset: 0, EncodedSize: 1}}
	blob := makeArchiveIndex(entries)

	// Corrupt the version byte → bad format.
	bad := append([]byte(nil), blob...)
	bad[len(bad)-archiveFooterLen+16] = 99
	if _, err := ParseArchiveIndex(bad); !errors.Is(err, casc.ErrBadFormat) {
		t.Fatalf("bad version: want ErrBadFormat, got %v", err)
	}

	// Flip a footer hash byte → corruption.
	bad = append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := ParseArchiveIndex(bad); !errors.Is(err, casc.ErrFileCorrupt) {
		t.Fatalf("bad hash: want ErrFileCorrupt, got %v", err)
	}
}

func TestArchiveSet_Lookup(t *testing.T) {
	entries := []ArchiveIndexEntry{
		{EKey: ekey(0xAB), Offset: 42, EncodedSize: 1024},
	}
	idx, err := ParseArchiveIndex(makeArchiveIndex(entries))
	if err != nil {
		t.Fatal(err)
	}
	var hash [casc.MD5HashSize]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	set := NewArchiveSet()
	set.Add(hash, idx)
	if set.Len() != 1 {
		t.Fatalf("len=%d", set.Len())
	}
	loc, ok := set.Lookup(ekey(0xAB))
	if !ok {
		t.Fatal("lookup miss")
	}
	if loc.Offset != 42 || loc.EncodedSize != 1024 {
		t.Fatalf("loc=%+v", loc)
	}
	if loc.ArchiveHashHex != hex.EncodeToString(hash[:]) {
		t.Fatalf("hash hex %q", loc.ArchiveHashHex)
	}
	if _, ok := set.Lookup(ekey(0x00)); ok {
		t.Fatal("unexpected lookup hit on missing key")
	}
}

// Sanity check on the manual MD5 logic — independent of EncodeArchiveIndex.
func TestArchiveIndex_FooterHashFormula(t *testing.T) {
	var f [archiveFooterLen]byte
	f[16] = 1                                  // Version
	f[19] = 4                                  // PageSizeKB
	f[20] = 4                                  // OffsetBytes
	f[21] = 4                                  // SizeBytes
	f[22] = 16                                 // EKeyLength
	f[23] = 8                                  // FooterHashBytes
	binary.LittleEndian.PutUint32(f[24:28], 0) // ElementCount
	sum := md5.Sum(f[16:])
	copy(f[28:36], sum[:8])

	// Build a 1-page (4KB) all-zero body so the index parses cleanly.
	body := make([]byte, 4096+casc.MD5HashSize)
	pageSum := md5.Sum(body[:4096])
	copy(body[4096:], pageSum[:])

	blob := append(body, f[:]...)
	idx, err := ParseArchiveIndex(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(idx.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(idx.Entries))
	}
	if !bytes.Equal(idx.Footer.FooterHash[:8], sum[:8]) {
		t.Fatal("footer hash mismatch")
	}
}
