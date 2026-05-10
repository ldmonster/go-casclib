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
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/hashes"
)

// buildSyntheticV1 constructs a minimal valid V1 index containing the given
// entries. Layout: 48-byte header + ekeyCount1 entries (block 1) + ekeyCount2
// entries (block 2). All entries are 18 bytes (9 EKey + 5 offset + 4 size).
func buildSyntheticV1(t *testing.T, bucket byte, count1, count2 int) ([]byte, []EKeyEntry) {
	t.Helper()
	const entryLen = 18
	hdr := make([]byte, 48)
	binary.LittleEndian.PutUint16(hdr[0:2], 0x05)
	hdr[2] = bucket
	hdr[3] = 0
	binary.LittleEndian.PutUint32(hdr[4:8], 0xAAAA5555)
	binary.LittleEndian.PutUint64(hdr[8:16], 0x40000000)  // field_8 (must be != 0)
	binary.LittleEndian.PutUint64(hdr[16:24], 0x40000000) // SegmentSize
	hdr[24] = 4                                           // EncodedSizeLength
	hdr[25] = 5                                           // StorageOffsetLength
	hdr[26] = 9                                           // EKeyLength
	hdr[27] = 30                                          // FileOffsetBits
	binary.LittleEndian.PutUint32(hdr[28:32], uint32(count1))
	binary.LittleEndian.PutUint32(hdr[32:36], uint32(count2))

	entries := make([]EKeyEntry, 0, count1+count2)
	mkEntries := func(n int, base byte) []byte {
		buf := make([]byte, n*entryLen)
		for i := 0; i < n; i++ {
			off := i * entryLen
			for j := 0; j < 9; j++ {
				buf[off+j] = base + byte(i) + byte(j)
			}
			// Storage offset: archIdx=base, fileOffs = i*0x1000.
			fileOffs := uint64(i) * 0x1000
			storeOff := (uint64(base) << 30) | fileOffs
			for k := 0; k < 5; k++ {
				buf[off+9+k] = byte(storeOff >> uint(8*(4-k)))
			}
			encSize := uint32(0x10000 + i)
			binary.BigEndian.PutUint32(buf[off+14:off+18], encSize)
			var ekey [16]byte
			copy(ekey[:9], buf[off:off+9])
			entries = append(entries, EKeyEntry{
				EKey:         ekey,
				ArchiveIndex: uint32(base),
				ArchiveOffs:  uint32(fileOffs),
				EncodedSize:  encSize,
			})
		}
		return buf
	}
	block1 := mkEntries(count1, 1)
	block2 := mkEntries(count2, 2)
	binary.LittleEndian.PutUint32(hdr[36:40], hashes.HashLittle(block1, 0))
	binary.LittleEndian.PutUint32(hdr[40:44], hashes.HashLittle(block2, 0))
	binary.LittleEndian.PutUint32(hdr[44:48], 0)
	binary.LittleEndian.PutUint32(hdr[44:48], hashes.HashLittle(hdr, 0))

	full := make([]byte, 0, len(hdr)+len(block1)+len(block2))
	full = append(full, hdr...)
	full = append(full, block1...)
	full = append(full, block2...)
	return full, entries
}

func TestParseV1(t *testing.T) {
	data, want := buildSyntheticV1(t, 0x03, 2, 3)
	idx, err := Parse(data, 0x03)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if idx.Header.IndexVersion != 5 {
		t.Errorf("version = %d, want 5", idx.Header.IndexVersion)
	}
	if idx.Header.EKeyCount != 5 {
		t.Errorf("count = %d", idx.Header.EKeyCount)
	}
	if len(idx.Entries) != len(want) {
		t.Fatalf("entries len = %d, want %d", len(idx.Entries), len(want))
	}
	for i := range want {
		if idx.Entries[i].ArchiveIndex != want[i].ArchiveIndex {
			t.Errorf("entry[%d] arch = %d, want %d",
				i, idx.Entries[i].ArchiveIndex, want[i].ArchiveIndex)
		}
		if idx.Entries[i].ArchiveOffs != want[i].ArchiveOffs {
			t.Errorf("entry[%d] offs = %#x, want %#x",
				i, idx.Entries[i].ArchiveOffs, want[i].ArchiveOffs)
		}
		if idx.Entries[i].EncodedSize != want[i].EncodedSize {
			t.Errorf("entry[%d] size = %#x, want %#x",
				i, idx.Entries[i].EncodedSize, want[i].EncodedSize)
		}
		if idx.Entries[i].EKey != want[i].EKey {
			t.Errorf("entry[%d] ekey mismatch", i)
		}
	}
}

func TestParseV1WrongBucket(t *testing.T) {
	data, _ := buildSyntheticV1(t, 0x03, 1, 1)
	if _, err := Parse(data, 0x05); err == nil {
		t.Fatal("expected error for wrong bucket")
	}
}

func TestParseV1Corrupt(t *testing.T) {
	data, _ := buildSyntheticV1(t, 0x00, 1, 1)
	// Flip a byte in the entries section to break key hashes.
	data[50] ^= 0xFF
	if _, err := Parse(data, 0x00); err == nil {
		t.Fatal("expected error for corrupt entries")
	}
}

// buildSyntheticV2 constructs a minimal V2 index using a guarded V1 wrapper
// over the header and a single guarded entry block (method-1 hash).
func buildSyntheticV2(t *testing.T, bucket byte, n int) []byte {
	t.Helper()
	const entryLen = 18
	// Build header (16 bytes V2 struct).
	v2hdr := make([]byte, 16)
	binary.LittleEndian.PutUint16(v2hdr[0:2], 0x07)
	v2hdr[2] = bucket
	v2hdr[3] = 0
	v2hdr[4] = 4
	v2hdr[5] = 5
	v2hdr[6] = 9
	v2hdr[7] = 30
	binary.LittleEndian.PutUint64(v2hdr[8:16], 0x40000000)

	hdrGuard := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdrGuard[0:4], uint32(len(v2hdr)))
	binary.LittleEndian.PutUint32(hdrGuard[4:8], hashes.HashLittle(v2hdr, 0))

	// Build entries.
	entries := make([]byte, n*entryLen)
	for i := 0; i < n; i++ {
		off := i * entryLen
		for j := 0; j < 9; j++ {
			entries[off+j] = byte(i)*7 + byte(j)
		}
		binary.BigEndian.PutUint32(entries[off+14:off+18], uint32(0x1000+i))
	}

	// Build entries guarded block (method 1: hashlittle2 over each).
	var hashHigh, hashLow uint32
	for i := 0; i < n; i++ {
		hashHigh, hashLow = hashes.HashLittle2(entries[i*entryLen:(i+1)*entryLen], hashHigh, hashLow)
	}
	_ = hashLow
	entriesGuard := make([]byte, 8)
	binary.LittleEndian.PutUint32(entriesGuard[0:4], uint32(len(entries)))
	binary.LittleEndian.PutUint32(entriesGuard[4:8], hashHigh)

	// Layout: hdrGuard (8) + v2hdr (16) + 8-byte padding + entriesGuard (8) + entries.
	out := make([]byte, 0)
	out = append(out, hdrGuard...)
	out = append(out, v2hdr...)
	out = append(out, make([]byte, 8)...) // HeaderPadding
	out = append(out, entriesGuard...)
	out = append(out, entries...)
	return out
}

func TestParseV2(t *testing.T) {
	data := buildSyntheticV2(t, 0x07, 4)
	idx, err := Parse(data, 0x07)
	if err != nil {
		t.Fatalf("Parse V2: %v", err)
	}
	if idx.Header.IndexVersion != 7 {
		t.Errorf("version = %d, want 7", idx.Header.IndexVersion)
	}
	if len(idx.Entries) != 4 {
		t.Errorf("entries = %d, want 4", len(idx.Entries))
	}
	for i, e := range idx.Entries {
		if e.EncodedSize != uint32(0x1000+i) {
			t.Errorf("entry[%d].EncodedSize = %#x", i, e.EncodedSize)
		}
	}
}
