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

package index

import (
	"bytes"
	"testing"
)

func TestEncodeV1RoundTrip(t *testing.T) {
	entries := []EKeyEntry{
		makeEntry([9]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, 0, 0x100, 0x200),
		makeEntry([9]byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77}, 1, 0x300, 0x400),
		makeEntry([9]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90}, 0, 0x500, 0x600),
	}

	for _, bucket := range []byte{0, 5, 0x0F} {
		out, err := EncodeV1(entries, WriteOptions{BucketIndex: bucket, SegmentSize: 0x40000000})
		if err != nil {
			t.Fatalf("EncodeV1: %v", err)
		}

		f, err := Parse(out, bucket)
		if err != nil {
			t.Fatalf("Parse(bucket=%d): %v", bucket, err)
		}

		if got := len(f.Entries); got != len(entries) {
			t.Fatalf("entry count: got %d want %d", got, len(entries))
		}

		// Each input entry must be present in the parsed output (order
		// changes due to sort).
		for _, want := range entries {
			if !findEntry(f.Entries, want) {
				t.Fatalf("missing entry %x", want.EKey)
			}
		}
	}
}

func TestEncodeV1TwoBlocks(t *testing.T) {
	entries := make([]EKeyEntry, 16)
	for i := range entries {
		var k [9]byte

		k[0] = byte(i)
		entries[i] = makeEntry(k, uint32(i&1), uint32(i*0x100), uint32(0x40+i))
	}

	out, err := EncodeV1(entries, WriteOptions{BucketIndex: 0, Block1Count: 8})
	if err != nil {
		t.Fatalf("EncodeV1: %v", err)
	}

	f, err := Parse(out, 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(f.Entries) != 16 {
		t.Fatalf("expected 16 entries, got %d", len(f.Entries))
	}
}

func makeEntry(ekey [9]byte, archive, off, sz uint32) EKeyEntry {
	var e EKeyEntry

	copy(e.EKey[:], ekey[:])
	e.ArchiveIndex = archive
	e.ArchiveOffs = off
	e.EncodedSize = sz

	return e
}

func findEntry(haystack []EKeyEntry, want EKeyEntry) bool {
	for _, e := range haystack {
		if !bytes.Equal(e.EKey[:9], want.EKey[:9]) {
			continue
		}

		if e.ArchiveIndex == want.ArchiveIndex &&
			e.ArchiveOffs == want.ArchiveOffs &&
			e.EncodedSize == want.EncodedSize {
			return true
		}
	}

	return false
}
