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

// V1 index file writer.
//
// Emits the 40-byte V1 header followed by two key blocks (KeysHash1 /
// KeysHash2). The split point is the midpoint of the entry list, matching
// what real CascLib-produced V1 indexes look like (a primary block plus a
// trailing "added" block). Both blocks are sorted by EKey.
//
// C++ reference: CaptureIndexHeader_V1 in CascIndexFiles.cpp and
// FILE_INDEX_HEADER_V1 in CascStructs.h.

package index

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/hashes"
)

// WriteOptions controls EncodeV1.
type WriteOptions struct {
	BucketIndex byte
	// SegmentSize is stored in the header (as field_8). It must be non-
	// zero for the file to validate. A reasonable default is selected
	// when zero.
	SegmentSize uint64
	// Block1Count is the number of entries placed in the primary key
	// block. Remaining entries go into the secondary block. Pass 0 (or
	// >= len(entries)) to put everything in block 1.
	Block1Count int
}

// EncodeV1 builds a V1 .idx file from the given entries.
//
// Entries are sorted by full 9-byte EKey before emission so that the
// resulting file matches the canonical layout produced by CascLib.
func EncodeV1(entries []EKeyEntry, opts WriteOptions) ([]byte, error) {
	if opts.SegmentSize == 0 {
		opts.SegmentSize = 0x40000000
	}

	const (
		ekeyLen     byte = 9
		storeOffLen byte = 5
		encSizeLen  byte = 4
		fileOffsBit byte = 30
		entryLen         = int(ekeyLen) + int(storeOffLen) + int(encSizeLen)
		// FILE_INDEX_HEADER_V1 per CascStructs.h: 2+1+1+4 + 8+8 + 4 + 4+4+4+4+4 = 48.
		fullSize = 48
	)

	// Sort by EKey for determinism / parity with real archives.
	sorted := make([]EKeyEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return ekeyLess(sorted[i].EKey, sorted[j].EKey, int(ekeyLen))
	})

	block1 := opts.Block1Count
	if block1 <= 0 || block1 > len(sorted) {
		block1 = len(sorted)
	}

	block2 := len(sorted) - block1

	out := make([]byte, fullSize+(block1+block2)*entryLen)

	// Header (48 bytes).
	binary.LittleEndian.PutUint16(out[0:2], 0x05) // IndexVersion
	out[2] = opts.BucketIndex
	out[3] = 0                                                  // align_3
	binary.LittleEndian.PutUint32(out[4:8], 0)                  // field_4
	binary.LittleEndian.PutUint64(out[8:16], 0x4000_0000)       // field_8 (must be != 0)
	binary.LittleEndian.PutUint64(out[16:24], opts.SegmentSize) // SegmentSize
	out[24] = encSizeLen
	out[25] = storeOffLen
	out[26] = ekeyLen
	out[27] = fileOffsBit
	binary.LittleEndian.PutUint32(out[28:32], uint32(block1)) // EKeyCount1
	binary.LittleEndian.PutUint32(out[32:36], uint32(block2)) // EKeyCount2
	// 36..40 KeysHash1, 40..44 KeysHash2, 44..48 HeaderHash — filled below.

	off := fullSize

	fields := entryFields{
		EKeyLen:      int(ekeyLen),
		StoreOffLen:  int(storeOffLen),
		EncSizeLen:   int(encSizeLen),
		FileOffsBits: int(fileOffsBit),
	}

	// Block 1.
	for i := 0; i < block1; i++ {
		writeEntryV1(out[off:off+entryLen], sorted[i], fields)
		off += entryLen
	}

	keysHash1 := hashes.HashLittle(out[fullSize:fullSize+block1*entryLen], 0)
	binary.LittleEndian.PutUint32(out[36:40], keysHash1)

	// Block 2.
	for i := 0; i < block2; i++ {
		writeEntryV1(out[off:off+entryLen], sorted[block1+i], fields)
		off += entryLen
	}

	block2Start := fullSize + block1*entryLen
	keysHash2 := hashes.HashLittle(out[block2Start:block2Start+block2*entryLen], 0)
	binary.LittleEndian.PutUint32(out[40:44], keysHash2)

	// HeaderHash — hashlittle over the first 48 bytes with the HeaderHash
	// field zeroed.
	hdrCopy := make([]byte, fullSize)
	copy(hdrCopy, out[:fullSize])
	binary.LittleEndian.PutUint32(hdrCopy[44:48], 0)
	binary.LittleEndian.PutUint32(out[44:48], hashes.HashLittle(hdrCopy, 0))

	return out, nil
}

type entryFields struct {
	EKeyLen, StoreOffLen, EncSizeLen, FileOffsBits int
}

func writeEntryV1(b []byte, e EKeyEntry, f entryFields) {
	copy(b[:f.EKeyLen], e.EKey[:f.EKeyLen])

	storage := (uint64(e.ArchiveIndex) << f.FileOffsBits) | uint64(e.ArchiveOffs)
	writeBE(b[f.EKeyLen:f.EKeyLen+f.StoreOffLen], storage)
	writeBE(b[f.EKeyLen+f.StoreOffLen:f.EKeyLen+f.StoreOffLen+f.EncSizeLen], uint64(e.EncodedSize))
}

func writeBE(b []byte, v uint64) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

func ekeyLess(a, b casc.EKey, n int) bool {
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}

	return false
}

// IndexFileName returns the canonical V2 file name for a given bucket
// and sub-index version (e.g. (0, 0) → "0000000000.idx"). CascLib's
// V2 mask is "##########.idx" — exactly 10 hex digits (2 for the
// bucket byte + 8 for the sub-index counter).
func IndexFileName(bucket byte, subIndex uint32) string {
	return fmt.Sprintf("%02x%08x.idx", bucket, subIndex)
}
